#include "winx/pipeline.hpp"

#include <algorithm>
#include <format>

#include "winx/apple_id.hpp"
#include "winx/auth_session.hpp"
#include "winx/bundler.hpp"
#include "winx/device_services.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/lockdown.hpp"
#include "winx/project.hpp"
#include "winx/provisioner.hpp"
#include "winx/sdk.hpp"
#include "winx/text.hpp"
#include "winx/usbmux.hpp"

namespace winx::engine {
namespace {

namespace fs = std::filesystem;

void emit(const EventSink& sink, Event::Kind kind, std::string text, int percent = -1) {
    if (!sink) return;
    Event event;
    event.kind = kind;
    event.text = std::move(text);
    event.percent = percent;
    sink(event);
}

// The user's entitlements file may add keys, but identity comes from the profile.
plist::Value merge_entitlements(const plist::Value& from_profile, const plist::Value& from_user) {
    plist::Dict merged = from_profile.as_dict();
    if (from_user.is<plist::Dict>()) {
        for (const auto& [key, value] : from_user.as_dict().items()) {
            if (key == "application-identifier" || key == "com.apple.developer.team-identifier") {
                continue;
            }
            merged.set(key, value);
        }
    }
    return merged;
}

}  // namespace

TargetDevice resolve_attached_device(const std::string& udid) {
    const device::UsbmuxEndpoint endpoint;
    const std::vector<device::UsbmuxDevice> devices = device::UsbmuxClient(endpoint).list_devices();
    if (devices.empty()) throw device::LockdownError("no device is attached");

    const device::UsbmuxDevice* chosen = nullptr;
    for (const device::UsbmuxDevice& candidate : devices) {
        if (udid.empty() || candidate.udid == udid) {
            if (chosen && chosen->udid != candidate.udid) {
                throw device::LockdownError("several devices are attached; choose one");
            }
            if (!chosen || candidate.connection == device::ConnectionType::Usb) chosen = &candidate;
        }
    }
    if (!chosen) throw device::LockdownError(std::format("device {} is not attached", udid));

    TargetDevice target;
    target.udid = chosen->udid;
    try {
        target.name = device::query_device_info(endpoint, chosen->device_id).name;
    } catch (const std::exception&) {
        // The name is only used as a label in the developer portal.
    }
    if (target.name.empty()) target.name = "iPhone";
    return target;
}

SigningMaterial provision_with_stored_sign_in(const std::string& bundle_id,
                                              const TargetDevice& target,
                                              const std::function<void(const std::string&)>& log) {
    const auth::AuthStore store(app_data_dir());
    const auth::AuthState state = store.load();
    const http::Client client;
    auth::DeveloperApi api(auth::make_transport(state, store, client));
    auth::IdentityStore identities(app_data_dir());
    auth::Provisioner provisioner(api, identities, log);

    auth::ProvisionRequest request;
    request.bundle_id = bundle_id;
    request.device_udid = target.udid;
    request.device_name = target.name;
    request.account = state.account();
    auth::ProvisionResult provisioned = provisioner.provision(request);
    const auth::AppleCertificates apple =
        auth::load_apple_certificates(client.sender(), store.directory());

    SigningMaterial material;
    material.provisioning_profile = provisioned.profile.raw;
    material.entitlements = std::move(provisioned.entitlements);
    auto identity = std::make_shared<auth::SigningIdentity>(std::move(provisioned.identity));
    material.credentials.certificate = identity->certificate();
    material.credentials.private_key = identity->key().handle();
    material.credentials.chain = {apple.wwdr_g3, apple.root};
    material.credentials.common_name = identity->info().common_name;
    material.credentials.team_id = identity->info().organizational_unit;
    material.keep_alive = std::move(identity);
    return material;
}

void install_on_device(const fs::path& bundle, const TargetDevice& target,
                       const std::function<void(const std::string&, int)>& progress) {
    device::DeviceConnection connection = device::DeviceConnection::open({}, target.udid);
    device::install_app(connection, bundle, progress);
}

PipelineResult run_pipeline(const PipelineOptions& options, const EventSink& sink) {
    PipelineResult result;
    try {
        emit(sink, Event::Kind::Stage, "Preparing");
        const build::ProjectConfig config = build::ProjectConfig::load(options.project_dir);
        const build::Toolchain toolchain = build::find_toolchain(options.swift);
        const fs::path sdk_dir = options.sdk_dir.empty() ? build::default_sdk_dir() : options.sdk_dir;
        const auto sdk = build::find_installed_sdk(sdk_dir);
        if (!sdk) {
            throw build::BuildError(
                "the iOS SDK is not installed; run `winx sdk install <Xcode.xip>` first");
        }
        emit(sink, Event::Kind::Log,
             std::format("{} with {}", toolchain.version_text, sdk->sdk_name));

        emit(sink, Event::Kind::Stage, "Building");
        build::BuildRequest build_request;
        build_request.project_dir = options.project_dir;
        build_request.config = config;
        build_request.toolchain = toolchain;
        build_request.sdk_bundles_dir = sdk_dir;
        build_request.release = options.release;
        build_request.stop = options.stop;
        build_request.on_output = [&](std::string_view line) {
            emit(sink, Event::Kind::Log, std::string(line));
        };
        build_request.on_diagnostic = [&](const build::Diagnostic& diagnostic) {
            if (!sink) return;
            Event event;
            event.kind = Event::Kind::Diagnostic;
            event.text = diagnostic.message;
            event.diagnostic = diagnostic;
            sink(event);
        };
        const build::BuildResult built = build::build_package(build_request);
        result.diagnostics = built.diagnostics;
        result.product = built.product;
        if (built.cancelled) {
            result.cancelled = true;
            result.error = "cancelled";
            return result;
        }
        if (!built.success) {
            const auto errors = std::count_if(
                built.diagnostics.begin(), built.diagnostics.end(), [](const auto& diagnostic) {
                    return diagnostic.severity == build::Diagnostic::Severity::Error;
                });
            result.error = errors > 0 ? std::format("the build failed with {} error(s)", errors)
                                      : std::format("the build failed (swift exited with {})",
                                                    built.exit_code);
            return result;
        }

        emit(sink, Event::Kind::Stage, "Packaging");
        build::BundleRequest bundle_request;
        bundle_request.project_dir = options.project_dir;
        bundle_request.config = config;
        bundle_request.product = built.product;
        bundle_request.deployment_target = built.package.ios_deployment_target;
        bundle_request.sdk_version = sdk->version;
        bundle_request.executable = built.executable;
        bundle_request.bin_dir = built.bin_dir;
        bundle_request.output_dir = options.project_dir / L".build" / L"winx" / L"products";
        const build::BundleResult bundled = build::assemble_bundle(bundle_request);
        for (const std::string& warning : bundled.warnings) {
            emit(sink, Event::Kind::Warning, warning);
        }
        result.bundle = bundled.bundle;
        result.bundle_id = bundled.bundle_id;
        if (!options.sign) {
            result.success = true;
            return result;
        }
        if (options.stop.stop_requested()) {
            result.cancelled = true;
            result.error = "cancelled";
            return result;
        }

        emit(sink, Event::Kind::Stage, "Provisioning");
        const TargetDevice target = options.resolve_device ? options.resolve_device(options.udid)
                                                           : resolve_attached_device(options.udid);
        const auto log = [&](const std::string& line) { emit(sink, Event::Kind::Log, line); };
        SigningMaterial material =
            options.provision ? options.provision(bundled.bundle_id, target, log)
                              : provision_with_stored_sign_in(bundled.bundle_id, target, log);
        if (!config.entitlements_path.empty()) {
            const fs::path path = options.project_dir / to_wide(config.entitlements_path);
            material.entitlements =
                merge_entitlements(material.entitlements, plist::load_file(path));
        }

        emit(sink, Event::Kind::Stage, "Signing");
        codesign::BundleSignOptions sign_options;
        sign_options.entitlements = material.entitlements;
        sign_options.provisioning_profile = material.provisioning_profile;
        sign_options.log = log;
        codesign::sign_bundle(bundled.bundle, material.credentials, sign_options);
        if (const auto problems = codesign::verify_bundle(bundled.bundle); !problems.empty()) {
            result.error = "the signed bundle failed its self-check: " + problems.front();
            return result;
        }
        if (!options.install) {
            result.success = true;
            return result;
        }
        if (options.stop.stop_requested()) {
            result.cancelled = true;
            result.error = "cancelled";
            return result;
        }

        emit(sink, Event::Kind::Stage, "Installing");
        const auto progress = [&](const std::string& stage, int percent) {
            emit(sink, Event::Kind::Progress, stage, percent);
        };
        if (options.install_bundle) {
            options.install_bundle(bundled.bundle, target, progress);
        } else {
            install_on_device(bundled.bundle, target, progress);
        }
        result.success = true;
    } catch (const std::exception& error) {
        result.error = error.what();
    }
    return result;
}

std::vector<Prerequisite> check_prerequisites() {
    std::vector<Prerequisite> items;

    Prerequisite toolchain{"Swift toolchain", false, {}};
    try {
        const build::Toolchain found = build::find_toolchain();
        toolchain.detail = found.version_text;
        toolchain.ready = std::pair{found.major, found.minor} >=
                          std::pair{build::kMinimumSwiftMajor, build::kMinimumSwiftMinor};
        if (!toolchain.ready) {
            toolchain.detail += std::format(" (needs {}.{} or newer)", build::kMinimumSwiftMajor,
                                            build::kMinimumSwiftMinor);
        }
    } catch (const std::exception& error) {
        toolchain.detail = error.what();
    }
    items.push_back(std::move(toolchain));

    Prerequisite sdk{"iOS SDK", false, {}};
    try {
        if (const auto installed = build::find_installed_sdk(build::default_sdk_dir())) {
            sdk.ready = true;
            sdk.detail = installed->sdk_name;
        } else {
            sdk.detail = "not installed; run `winx sdk install <Xcode.xip>`";
        }
    } catch (const std::exception& error) {
        sdk.detail = error.what();
    }
    items.push_back(std::move(sdk));

    Prerequisite account{"Apple sign-in", false, {}};
    try {
        const auth::AuthState state = auth::AuthStore(app_data_dir()).load();
        account.ready = state.mode != auth::AuthState::Mode::None;
        account.detail = state.mode == auth::AuthState::Mode::ApiKey
                             ? "API key " + state.key_id
                             : state.mode == auth::AuthState::Mode::AppleId
                                   ? state.apple_id + " (" + state.team_id + ")"
                                   : "not signed in; run `winx auth login`";
    } catch (const std::exception& error) {
        account.detail = error.what();
    }
    items.push_back(std::move(account));

    Prerequisite service{"Apple Mobile Device Service", false, {}};
    Prerequisite phone{"Device", false, {}};
    try {
        const auto devices = device::UsbmuxClient().list_devices();
        service.ready = true;
        service.detail = "running";
        if (devices.empty()) {
            phone.detail = "none attached";
        } else {
            phone.ready = true;
            phone.detail = devices.front().udid;
        }
    } catch (const std::exception&) {
        service.detail = "not reachable; install Apple Devices or iTunes";
        phone.detail = "unknown";
    }
    items.push_back(std::move(service));
    items.push_back(std::move(phone));
    return items;
}

}  // namespace winx::engine
