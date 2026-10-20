#include <windows.h>

#include <CLI/CLI.hpp>

#include <exception>
#include <iostream>

#include "commands.hpp"

int main(int argc, char** argv) {
    // Device names are UTF-8 and often contain non-ASCII punctuation.
    SetConsoleOutputCP(CP_UTF8);

    CLI::App app{"WinXcode: build, sign and install iOS apps from Windows"};
    argv = app.ensure_utf8(argv);
    app.require_subcommand(1);

    // ---- devices ----
    winx::cli::DevicesOptions devices_options;
    CLI::App* devices = app.add_subcommand("devices", "List attached iOS devices");
    devices->add_flag("-w,--watch", devices_options.watch,
                      "Keep running and report devices as they attach and detach");
    devices->add_flag("-v,--verbose", devices_options.verbose,
                      "Also show pairing record details");
    devices->add_flag("--paired", devices_options.paired,
                      "List the devices this PC holds a pairing record for")
        ->excludes("--watch");
    devices->add_option("--host", devices_options.host, "usbmux host")->group("Advanced");
    devices->add_option("--port", devices_options.port, "usbmux port")->group("Advanced");

    // ---- auth ----
    CLI::App* auth = app.add_subcommand("auth", "Manage Apple Developer sign-in");
    auth->require_subcommand(1);
    winx::cli::AuthLoginOptions login_options;
    CLI::App* login = auth->add_subcommand("login", "Sign in with an API key or an Apple ID");
    login->add_option("-m,--mode", login_options.mode,
                      "'key' for an App Store Connect API key (official), 'password' for an "
                      "Apple ID (unofficial)")
        ->required()
        ->check(CLI::IsMember({"key", "password"}));
    login->add_option("--key-id", login_options.key_id, "API key ID");
    login->add_option("--issuer-id", login_options.issuer_id, "API issuer ID");
    login->add_option("--key", login_options.key_path, "Path to the AuthKey .p8 file");
    login->add_option("--apple-id", login_options.apple_id, "Apple ID e-mail address");
    login->add_option("--team", login_options.team_id, "Team ID to use when there are several");
    login->add_option("--anisette-url", login_options.anisette_url,
                      "anisette-v3 server to use instead of the default");
    login->add_flag("--accept-warning", login_options.accept_warning,
                    "Do not ask for confirmation of the warning text");
    CLI::App* status = auth->add_subcommand("status", "Show the current sign-in");
    CLI::App* logout = auth->add_subcommand("logout", "Remove stored credentials");

    // ---- ds ----
    winx::cli::DsOptions ds_options;
    CLI::App* ds = app.add_subcommand("ds", "Apple Developer Services");
    ds->add_option("action", ds_options.action,
                   "teams | devices | identifiers | certificates | profiles | provision")
        ->required()
        ->check(CLI::IsMember(
            {"teams", "devices", "identifiers", "certificates", "profiles", "provision"}));
    ds->add_option("--bundle-id", ds_options.bundle_id, "Bundle identifier to provision");
    ds->add_option("--udid", ds_options.udid, "Device to provision for (default: the attached one)");
    ds->add_option("--device-name", ds_options.device_name,
                   "Name to register the device under if it is new");
    ds->add_option("-o,--out", ds_options.output_dir,
                   "Directory for embedded.mobileprovision and Entitlements.plist");

    // ---- sign ----
    winx::cli::SignOptions sign_options;
    CLI::App* sign = app.add_subcommand("sign", "Code-sign an .app bundle or a Mach-O file");
    sign->add_option("target", sign_options.target, "Bundle directory or Mach-O file")->required();
    sign->add_option("-p,--profile", sign_options.profile_path,
                     "Provisioning profile to embed (default: the one already in the bundle)");
    sign->add_option("-e,--entitlements", sign_options.entitlements_path,
                     "Entitlements plist (default: derived from the profile)");
    sign->add_option("-i,--identifier", sign_options.identifier,
                     "Signing identifier for a bare Mach-O file");
    sign->add_flag("--adhoc", sign_options.ad_hoc,
                   "Hash-only signature with no certificate; not accepted by retail devices");
    sign->add_flag("--verify", sign_options.verify,
                   "Check an existing signature instead of signing");

    // ---- device commands ----
    winx::cli::DeviceOptions device_options;
    const auto add_device_flags = [&](CLI::App* command) {
        command->add_option("-u,--udid", device_options.udid,
                            "Device to use (default: the only attached device)");
        command->add_option("--host", device_options.host, "usbmux host")->group("Advanced");
        command->add_option("--port", device_options.port, "usbmux port")->group("Advanced");
    };
    CLI::App* install =
        app.add_subcommand("install", "Install a signed .app bundle or .ipa on a device");
    install->add_option("bundle", device_options.target, "Path to the .app bundle or .ipa file")
        ->required();
    add_device_flags(install);
    CLI::App* uninstall = app.add_subcommand("uninstall", "Remove an app from a device");
    uninstall->add_option("bundle-id", device_options.target, "Bundle identifier")->required();
    add_device_flags(uninstall);

    CLI::App* device = app.add_subcommand("device", "Inspect a paired device");
    device->require_subcommand(1);
    CLI::App* apps = device->add_subcommand("apps", "List user-installed apps");
    add_device_flags(apps);
    CLI::App* log = device->add_subcommand("log", "Stream the device log until Ctrl+C");
    add_device_flags(log);
    CLI::App* devmode = device->add_subcommand("devmode", "Show Developer Mode status");
    devmode->add_flag("--reveal", device_options.reveal,
                      "Make the Developer Mode switch appear in Settings");
    add_device_flags(devmode);

    // ---- project commands ----
    winx::cli::BuildOptions build_options;
    const auto add_build_flags = [&](CLI::App* command) {
        command->add_option("-C,--project", build_options.project_dir,
                            "Project directory (default: the current directory)");
        command->add_flag("--release", build_options.release, "Build with optimisations");
        command->add_option("--swift", build_options.swift_path, "Path to swift.exe")
            ->group("Advanced");
    };
    CLI::App* build = app.add_subcommand("build", "Build the project into an unsigned .app");
    add_build_flags(build);
    CLI::App* dev = app.add_subcommand("dev", "Build, sign and install on the attached device");
    add_build_flags(dev);
    dev->add_option("-u,--udid", build_options.udid,
                    "Device to install on (default: the only attached device)");

    CLI::App* export_ipa =
        app.add_subcommand("export", "Build, sign and pack the app as an .ipa");
    add_build_flags(export_ipa);
    export_ipa->add_option("-o,--output", build_options.ipa_path,
                           "Where to write the .ipa (default: <project>\\<Product>.ipa)");
    export_ipa->add_flag("--unsigned", build_options.unsigned_ipa,
                         "Skip provisioning and signing, for tools that sign the .ipa themselves");
    export_ipa->add_option("-u,--udid", build_options.udid,
                           "Device to provision for (default: the only attached device)");

    winx::cli::NewOptions new_options;
    CLI::App* create = app.add_subcommand("new", "Create a new SwiftUI project");
    create->add_option("name", new_options.name, "Project and product name")->required();
    create->add_option("--org-id", new_options.org_id, "Bundle identifier prefix");

    winx::cli::SdkOptions sdk_options;
    CLI::App* sdk = app.add_subcommand("sdk", "Manage the iOS SDK");
    sdk->require_subcommand(1);
    CLI::App* sdk_install = sdk->add_subcommand("install", "Build the SDK from your Xcode.xip");
    sdk_install->add_option("xip", sdk_options.xip, "Path to Xcode.xip")->required();
    sdk_install->add_flag("--accept", sdk_options.accept, "Do not ask for confirmation");
    CLI::App* sdk_status = sdk->add_subcommand("status", "Show the installed SDK");

    CLI::App* setup = app.add_subcommand("setup", "Check everything needed to build and install");

    CLI11_PARSE(app, argc, argv);

    try {
        if (build->parsed()) return winx::cli::run_build(build_options);
        if (dev->parsed()) return winx::cli::run_dev(build_options);
        if (export_ipa->parsed()) return winx::cli::run_export(build_options);
        if (create->parsed()) return winx::cli::run_new(new_options);
        if (sdk_install->parsed()) {
            sdk_options.action = "install";
            return winx::cli::run_sdk(sdk_options);
        }
        if (sdk_status->parsed()) {
            sdk_options.action = "status";
            return winx::cli::run_sdk(sdk_options);
        }
        if (setup->parsed()) return winx::cli::run_setup();
        if (install->parsed()) return winx::cli::run_install(device_options);
        if (uninstall->parsed()) return winx::cli::run_uninstall(device_options);
        if (apps->parsed()) return winx::cli::run_apps(device_options);
        if (log->parsed()) return winx::cli::run_log(device_options);
        if (devmode->parsed()) return winx::cli::run_devmode(device_options);
        if (sign->parsed()) return winx::cli::run_sign(sign_options);
        if (devices->parsed()) return winx::cli::run_devices(devices_options);
        if (login->parsed()) return winx::cli::run_auth_login(login_options);
        if (status->parsed()) return winx::cli::run_auth_status();
        if (logout->parsed()) return winx::cli::run_auth_logout();
        if (ds->parsed()) return winx::cli::run_ds(ds_options);
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
