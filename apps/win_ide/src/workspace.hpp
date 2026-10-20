#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "winx/pipeline.hpp"
#include "winx/project.hpp"
#include "winx/swiftpm.hpp"
#include "winx/usbmux.hpp"

// Everything the IDE knows that is not pixels: the open project, attached
// devices, the running build, and the logs. Background threads feed queues
// that poll() drains on the UI thread, so the UI never blocks and never
// touches shared state without the lock.
namespace winx::ide {

struct FileNode {
    std::string name;
    std::filesystem::path path;
    bool directory = false;
    std::vector<FileNode> children;
};

// Directory tree for the navigator: folders first, then files, each sorted
// case-insensitively. Build output and VCS directories are left out.
FileNode scan_project(const std::filesystem::path& root);

struct ConsoleLine {
    enum class Kind { Plain, Stage, Warning, Error, Success };
    Kind kind = Kind::Plain;
    std::string text;
};

struct DeviceEntry {
    std::uint32_t device_id = 0;
    std::string udid;
    std::string name;
    std::string os_version;
    bool usb = true;

    std::string label() const;
};

// Export signs for the selected device and writes <project>\<Product>.ipa.
enum class RunMode { Build, Run, Export };

class Workspace {
public:
    Workspace();
    ~Workspace();
    Workspace(const Workspace&) = delete;
    Workspace& operator=(const Workspace&) = delete;

    // ---- Project ----
    // Returns an empty string on success, otherwise why the folder was refused.
    std::string open_project(const std::filesystem::path& directory);
    bool has_project() const noexcept { return !project_dir_.empty(); }
    const std::filesystem::path& project_dir() const noexcept { return project_dir_; }
    const FileNode& tree() const noexcept { return tree_; }
    build::ProjectConfig& config() noexcept { return config_; }
    // Writes xtool.yml; returns an error message or an empty string.
    std::string save_config();
    // Product name, known after the first build; the folder name until then.
    const std::string& scheme() const noexcept { return scheme_; }
    const std::string& deployment_target() const noexcept { return deployment_target_; }

    // ---- Per-frame update ----
    // Applies everything the background threads produced since the last
    // call. Returns true if anything changed.
    bool poll();

    // ---- Run ----
    void start(RunMode mode);
    void stop();
    bool running() const noexcept { return running_; }
    const std::string& stage() const noexcept { return stage_; }
    int progress() const noexcept { return progress_; }
    // Outcome of the last finished run, for the status area.
    const std::string& last_result() const noexcept { return last_result_; }
    bool last_succeeded() const noexcept { return last_succeeded_; }

    // ---- Logs ----
    const std::vector<ConsoleLine>& build_log() const noexcept { return build_log_; }
    const std::vector<build::Diagnostic>& diagnostics() const noexcept { return diagnostics_; }
    const std::vector<std::string>& device_log() const noexcept { return device_log_; }
    void clear_build_log();
    void clear_device_log();
    // Incremented whenever a log gains lines; the console uses it to auto-scroll.
    std::uint64_t build_log_revision() const noexcept { return build_log_revision_; }
    std::uint64_t device_log_revision() const noexcept { return device_log_revision_; }

    // ---- Devices ----
    const std::vector<DeviceEntry>& devices() const noexcept { return devices_; }
    int selected_device() const noexcept { return selected_device_; }
    void select_device(int index);
    const std::string& device_status() const noexcept { return device_status_; }
    bool device_log_running() const noexcept { return device_log_running_; }
    void set_device_log_enabled(bool enabled);

    // ---- Environment ----
    const std::vector<engine::Prerequisite>& prerequisites() const noexcept { return prerequisites_; }
    void refresh_prerequisites();

private:
    struct Shared;  // state written by background threads
    void ensure_listener();
    void start_watcher();
    void append_log(ConsoleLine::Kind kind, std::string text);

    std::filesystem::path project_dir_;
    FileNode tree_;
    build::ProjectConfig config_;
    std::string scheme_;
    std::string deployment_target_;

    bool running_ = false;
    std::string stage_;
    int progress_ = -1;
    std::string last_result_;
    bool last_succeeded_ = false;

    std::vector<ConsoleLine> build_log_;
    std::vector<build::Diagnostic> diagnostics_;
    std::vector<std::string> device_log_;
    std::uint64_t build_log_revision_ = 0;
    std::uint64_t device_log_revision_ = 0;

    std::vector<DeviceEntry> devices_;
    int selected_device_ = -1;
    std::string device_status_;
    bool device_log_running_ = false;
    bool device_log_wanted_ = false;
    std::string device_log_udid_;

    std::vector<engine::Prerequisite> prerequisites_;

    std::shared_ptr<Shared> shared_;
    std::unique_ptr<device::UsbmuxListener> listener_;
    std::chrono::steady_clock::time_point next_listener_attempt_{};
    std::jthread pipeline_thread_;
    std::jthread device_log_thread_;
    std::jthread watcher_thread_;
    std::jthread prerequisites_thread_;
};

}  // namespace winx::ide
