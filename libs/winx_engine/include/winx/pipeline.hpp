#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

#include "winx/codesign.hpp"
#include "winx/plist.hpp"
#include "winx/swiftpm.hpp"

// The whole "Run" action: build -> bundle -> provision -> sign -> install.
// The CLI's `winx dev` and the IDE's Run button both call run_pipeline and
// differ only in how they present the events.
namespace winx::engine {

struct Event {
    enum class Kind {
        Stage,       // a new step began; `text` names it
        Log,         // one line of tool output
        Diagnostic,  // a compiler error, warning or note
        Progress,    // `text` is the activity, `percent` 0-100 or -1
        Warning,
    };
    Kind kind = Kind::Log;
    std::string text;
    int percent = -1;
    std::optional<build::Diagnostic> diagnostic;
};
using EventSink = std::function<void(const Event&)>;

struct TargetDevice {
    std::string udid;
    std::string name;
};

// Everything the signer needs for one app on one device.
struct SigningMaterial {
    codesign::SigningCredentials credentials;
    std::vector<std::uint8_t> provisioning_profile;
    plist::Value entitlements;
    // Owns whatever `credentials.private_key` refers to.
    std::shared_ptr<void> keep_alive;
};

struct PipelineOptions {
    std::filesystem::path project_dir;
    std::string udid;  // empty: the only attached device
    bool release = false;
    // Stop after the named step: building always happens, signing and
    // installing can be left out.
    bool sign = true;
    bool install = true;
    std::optional<std::filesystem::path> swift;  // explicit swift.exe
    std::filesystem::path sdk_dir;               // default_sdk_dir() when empty
    std::stop_token stop;

    // Seams. Left empty, the pipeline talks to the attached device and to
    // Apple with the stored sign-in; tests substitute their own.
    std::function<TargetDevice(const std::string& udid)> resolve_device;
    std::function<SigningMaterial(const std::string& bundle_id, const TargetDevice& device,
                                  const std::function<void(const std::string&)>& log)>
        provision;
    std::function<void(const std::filesystem::path& bundle, const TargetDevice& device,
                       const std::function<void(const std::string&, int)>& progress)>
        install_bundle;
};

struct PipelineResult {
    bool success = false;
    bool cancelled = false;
    std::string error;  // empty on success
    std::string product;
    std::string bundle_id;
    std::filesystem::path bundle;
    std::vector<build::Diagnostic> diagnostics;
};

// Never throws for ordinary failures; they are reported in the result.
PipelineResult run_pipeline(const PipelineOptions& options, const EventSink& sink);

// The default seams.
TargetDevice resolve_attached_device(const std::string& udid);
SigningMaterial provision_with_stored_sign_in(const std::string& bundle_id,
                                              const TargetDevice& device,
                                              const std::function<void(const std::string&)>& log);
void install_on_device(const std::filesystem::path& bundle, const TargetDevice& device,
                       const std::function<void(const std::string&, int)>& progress);

// One line per prerequisite, for `winx setup` and the IDE's status panel.
struct Prerequisite {
    std::string name;
    bool ready = false;
    std::string detail;
};
std::vector<Prerequisite> check_prerequisites();

}  // namespace winx::engine
