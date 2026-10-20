#include "workspace.hpp"

#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <format>

#include "winx/device_services.hpp"
#include "winx/lockdown.hpp"
#include "winx/text.hpp"

namespace winx::ide {
namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

constexpr std::size_t kMaxLogLines = 5000;
constexpr int kMaxTreeDepth = 12;

bool hidden_from_navigator(const fs::path& path, bool directory) {
    const std::wstring name = path.filename().wstring();
    if (directory) {
        return name == L".build" || name == L".git" || name == L".swiftpm" || name == L".vs" ||
               path.extension() == L".app";
    }
    return name == L".DS_Store";
}

std::wstring lower(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), ::towlower);
    return text;
}

void scan_into(FileNode& node, int depth) {
    if (depth > kMaxTreeDepth) return;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(node.path, ec)) {
        const bool directory = entry.is_directory(ec);
        if (hidden_from_navigator(entry.path(), directory)) continue;
        FileNode child;
        child.path = entry.path();
        child.name = to_utf8(entry.path().filename().wstring());
        child.directory = directory;
        if (directory) scan_into(child, depth + 1);
        node.children.push_back(std::move(child));
    }
    std::sort(node.children.begin(), node.children.end(), [](const FileNode& a, const FileNode& b) {
        if (a.directory != b.directory) return a.directory;
        return lower(a.path.filename().wstring()) < lower(b.path.filename().wstring());
    });
}

struct DeviceChange {
    bool attached = false;
    std::uint32_t device_id = 0;
    DeviceEntry entry;
};

}  // namespace

FileNode scan_project(const fs::path& root) {
    FileNode node;
    node.path = root;
    node.name = to_utf8(root.filename().wstring());
    node.directory = true;
    scan_into(node, 0);
    return node;
}

std::string DeviceEntry::label() const {
    std::string text = name.empty() ? udid : name;
    if (!os_version.empty()) text += std::format(" (iOS {})", os_version);
    if (!usb) text += " - Wi-Fi";
    return text;
}

struct Workspace::Shared {
    std::mutex mutex;
    std::vector<engine::Event> events;
    std::optional<engine::PipelineResult> result;
    std::vector<DeviceChange> device_changes;
    std::string listener_error;
    std::vector<std::string> log_lines;
    bool log_ended = false;
    std::optional<std::vector<engine::Prerequisite>> prerequisites;
    std::atomic<bool> tree_dirty{false};
};

Workspace::Workspace() : shared_(std::make_shared<Shared>()) {
    ensure_listener();
    refresh_prerequisites();
}

Workspace::~Workspace() {
    // Ask every worker to stop before any of them is joined.
    pipeline_thread_.request_stop();
    device_log_thread_.request_stop();
    watcher_thread_.request_stop();
    prerequisites_thread_.request_stop();
    listener_.reset();
}

void Workspace::append_log(ConsoleLine::Kind kind, std::string text) {
    build_log_.push_back({kind, std::move(text)});
    if (build_log_.size() > kMaxLogLines) {
        build_log_.erase(build_log_.begin(), build_log_.begin() + (build_log_.size() - kMaxLogLines));
    }
    ++build_log_revision_;
}

void Workspace::clear_build_log() {
    build_log_.clear();
    diagnostics_.clear();
    ++build_log_revision_;
}

void Workspace::clear_device_log() {
    device_log_.clear();
    ++device_log_revision_;
}

std::string Workspace::open_project(const fs::path& directory) {
    std::error_code ec;
    if (!fs::is_directory(directory, ec)) return "The folder does not exist.";
    if (!fs::is_regular_file(directory / L"Package.swift", ec)) {
        return "This folder is not a Swift package (there is no Package.swift).";
    }
    build::ProjectConfig config;
    if (fs::is_regular_file(directory / L"xtool.yml", ec)) {
        try {
            config = build::ProjectConfig::load(directory);
        } catch (const build::ProjectError& error) {
            return error.what();
        }
    } else {
        // A plain package: give it a default identifier so it can be run.
        config.org_id = "com.example";
    }

    stop();
    project_dir_ = directory;
    config_ = std::move(config);
    scheme_ = config_.product.empty() ? to_utf8(directory.filename().wstring()) : config_.product;
    deployment_target_.clear();
    tree_ = scan_project(directory);
    clear_build_log();
    last_result_.clear();
    start_watcher();
    return {};
}

std::string Workspace::save_config() {
    try {
        config_.save(project_dir_);
        return {};
    } catch (const std::exception& error) {
        return error.what();
    }
}

void Workspace::start_watcher() {
    watcher_thread_ = std::jthread([shared = shared_, directory = project_dir_](std::stop_token stop) {
        const HANDLE change = FindFirstChangeNotificationW(
            directory.c_str(), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME);
        if (change == INVALID_HANDLE_VALUE) return;
        while (!stop.stop_requested()) {
            if (WaitForSingleObject(change, 250) == WAIT_OBJECT_0) {
                shared->tree_dirty = true;
                if (!FindNextChangeNotification(change)) break;
            }
        }
        FindCloseChangeNotification(change);
    });
}

void Workspace::ensure_listener() {
    if (listener_ && listener_->running()) return;
    const auto now = std::chrono::steady_clock::now();
    if (now < next_listener_attempt_) return;
    next_listener_attempt_ = now + 3s;

    // Whatever the old connection knew about is gone with it.
    listener_.reset();
    devices_.clear();
    selected_device_ = -1;
    try {
        const device::UsbmuxEndpoint endpoint;
        listener_ = std::make_unique<device::UsbmuxListener>(
            endpoint,
            [shared = shared_, endpoint](const device::DeviceEvent& event) {
                DeviceChange change;
                change.device_id = event.device_id;
                if (event.kind == device::DeviceEvent::Kind::Attached && event.device) {
                    change.attached = true;
                    change.entry.device_id = event.device_id;
                    change.entry.udid = event.device->udid;
                    change.entry.usb = event.device->connection != device::ConnectionType::Network;
                    // lockdownd can take a moment to come up after plug-in.
                    for (int attempt = 0; attempt < 4; ++attempt) {
                        try {
                            const device::DeviceInfo info =
                                device::query_device_info(endpoint, event.device_id);
                            change.entry.name = info.name;
                            change.entry.os_version = info.product_version;
                            break;
                        } catch (const std::exception&) {
                            std::this_thread::sleep_for(400ms);
                        }
                    }
                } else if (event.kind != device::DeviceEvent::Kind::Detached) {
                    return;
                }
                const std::lock_guard lock(shared->mutex);
                shared->device_changes.push_back(std::move(change));
            },
            [shared = shared_](const std::string& message) {
                const std::lock_guard lock(shared->mutex);
                shared->listener_error = message;
            });
        device_status_.clear();
    } catch (const std::exception&) {
        device_status_ = "Apple Mobile Device Service is not running";
    }
}

void Workspace::select_device(int index) {
    if (index < 0 || index >= static_cast<int>(devices_.size())) return;
    selected_device_ = index;
}

void Workspace::set_device_log_enabled(bool enabled) { device_log_wanted_ = enabled; }

void Workspace::refresh_prerequisites() {
    prerequisites_thread_ = std::jthread([shared = shared_](std::stop_token) {
        std::vector<engine::Prerequisite> found = engine::check_prerequisites();
        const std::lock_guard lock(shared->mutex);
        shared->prerequisites = std::move(found);
    });
}

void Workspace::start(RunMode mode) {
    if (running_ || !has_project()) return;
    if (pipeline_thread_.joinable()) pipeline_thread_.join();
    clear_build_log();

    engine::PipelineOptions options;
    options.project_dir = project_dir_;
    options.sign = mode != RunMode::Build;
    options.install = mode == RunMode::Run;
    if (mode == RunMode::Export) options.ipa = std::filesystem::path();
    if (mode != RunMode::Build) {
        // Even an exported .ipa is provisioned for one device.
        if (selected_device_ < 0) {
            append_log(ConsoleLine::Kind::Error, "No device is attached. Connect an iPhone and "
                                                 "unlock it, or use Product > Build.");
            last_result_ = "No device";
            last_succeeded_ = false;
            return;
        }
        options.udid = devices_[static_cast<std::size_t>(selected_device_)].udid;
    }

    running_ = true;
    stage_ = "Starting";
    progress_ = -1;
    last_result_.clear();
    pipeline_thread_ = std::jthread([shared = shared_, options](std::stop_token stop) mutable {
        options.stop = stop;
        engine::PipelineResult result =
            engine::run_pipeline(options, [&](const engine::Event& event) {
                const std::lock_guard lock(shared->mutex);
                shared->events.push_back(event);
            });
        const std::lock_guard lock(shared->mutex);
        shared->result = std::move(result);
    });
}

void Workspace::stop() {
    if (running_) pipeline_thread_.request_stop();
}

bool Workspace::poll() {
    ensure_listener();

    std::vector<engine::Event> events;
    std::optional<engine::PipelineResult> result;
    std::vector<DeviceChange> device_changes;
    std::vector<std::string> log_lines;
    std::string listener_error;
    bool log_ended = false;
    {
        const std::lock_guard lock(shared_->mutex);
        events.swap(shared_->events);
        result.swap(shared_->result);
        device_changes.swap(shared_->device_changes);
        log_lines.swap(shared_->log_lines);
        listener_error.swap(shared_->listener_error);
        log_ended = std::exchange(shared_->log_ended, false);
        if (shared_->prerequisites) {
            prerequisites_ = std::move(*shared_->prerequisites);
            shared_->prerequisites.reset();
        }
    }
    bool changed = !events.empty() || result || !device_changes.empty() || !log_lines.empty();

    for (engine::Event& event : events) {
        switch (event.kind) {
            case engine::Event::Kind::Stage:
                stage_ = event.text;
                progress_ = -1;
                append_log(ConsoleLine::Kind::Stage, event.text);
                break;
            case engine::Event::Kind::Log: {
                ConsoleLine::Kind kind = ConsoleLine::Kind::Plain;
                if (const auto diagnostic = build::parse_diagnostic(event.text)) {
                    if (diagnostic->severity == build::Diagnostic::Severity::Error) {
                        kind = ConsoleLine::Kind::Error;
                    } else if (diagnostic->severity == build::Diagnostic::Severity::Warning) {
                        kind = ConsoleLine::Kind::Warning;
                    }
                }
                append_log(kind, std::move(event.text));
                break;
            }
            case engine::Event::Kind::Diagnostic:
                if (event.diagnostic) diagnostics_.push_back(*event.diagnostic);
                break;
            case engine::Event::Kind::Progress:
                stage_ = event.text;
                progress_ = event.percent;
                break;
            case engine::Event::Kind::Warning:
                append_log(ConsoleLine::Kind::Warning, "warning: " + event.text);
                break;
        }
    }

    if (result) {
        running_ = false;
        progress_ = -1;
        stage_.clear();
        last_succeeded_ = result->success;
        if (!result->product.empty()) scheme_ = result->product;
        if (result->success) {
            last_result_ = result->bundle.empty() ? "Succeeded" : "Succeeded: " + result->bundle_id;
            append_log(ConsoleLine::Kind::Success, last_result_);
            if (!result->ipa.empty()) {
                append_log(ConsoleLine::Kind::Success,
                           "Exported " + to_utf8(result->ipa.wstring()));
            }
        } else {
            last_result_ = result->cancelled ? "Stopped" : "Failed";
            append_log(ConsoleLine::Kind::Error, result->cancelled ? "Stopped." : result->error);
        }
    }

    for (DeviceChange& change : device_changes) {
        const auto existing = std::find_if(devices_.begin(), devices_.end(), [&](const auto& d) {
            return d.device_id == change.device_id;
        });
        if (change.attached) {
            if (existing != devices_.end()) {
                *existing = std::move(change.entry);
            } else {
                devices_.push_back(std::move(change.entry));
            }
        } else if (existing != devices_.end()) {
            const int index = static_cast<int>(existing - devices_.begin());
            devices_.erase(existing);
            if (selected_device_ == index) {
                selected_device_ = -1;
            } else if (selected_device_ > index) {
                --selected_device_;
            }
        }
    }
    if (selected_device_ < 0 && !devices_.empty()) selected_device_ = 0;
    if (!listener_error.empty()) {
        device_status_ = "Lost contact with Apple Mobile Device Service";
        changed = true;
    }

    if (!log_lines.empty()) {
        for (std::string& line : log_lines) device_log_.push_back(std::move(line));
        if (device_log_.size() > kMaxLogLines) {
            device_log_.erase(device_log_.begin(),
                              device_log_.begin() + (device_log_.size() - kMaxLogLines));
        }
        ++device_log_revision_;
    }
    if (log_ended) device_log_running_ = false;

    // Keep the device log attached to the selected device while it is wanted.
    const std::string wanted_udid =
        device_log_wanted_ && selected_device_ >= 0
            ? devices_[static_cast<std::size_t>(selected_device_)].udid
            : std::string{};
    if (wanted_udid != device_log_udid_ || (!wanted_udid.empty() && !device_log_running_)) {
        device_log_thread_ = std::jthread();  // stops and joins the old stream
        device_log_udid_ = wanted_udid;
        device_log_running_ = false;
        if (!wanted_udid.empty()) {
            device_log_running_ = true;
            device_log_thread_ = std::jthread([shared = shared_, udid = wanted_udid](std::stop_token stop) {
                const auto push = [&](std::string line) {
                    const std::lock_guard lock(shared->mutex);
                    shared->log_lines.push_back(std::move(line));
                };
                try {
                    device::DeviceConnection connection = device::DeviceConnection::open({}, udid);
                    device::SyslogStream log = device::SyslogStream::open(connection);
                    while (!stop.stop_requested()) {
                        if (auto line = log.read_line(200ms)) push(std::move(*line));
                    }
                } catch (const std::exception& error) {
                    push(std::string("[device log stopped: ") + error.what() + "]");
                    // Do not reconnect in a tight loop if the device refuses.
                    for (int i = 0; i < 25 && !stop.stop_requested(); ++i) {
                        std::this_thread::sleep_for(200ms);
                    }
                }
                const std::lock_guard lock(shared->mutex);
                shared->log_ended = true;
            });
        }
        changed = true;
    }

    if (shared_->tree_dirty.exchange(false) && has_project()) {
        tree_ = scan_project(project_dir_);
        changed = true;
    }
    return changed;
}

}  // namespace winx::ide
