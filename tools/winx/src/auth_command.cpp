#include "commands.hpp"

#include <windows.h>

#include <chrono>
#include <format>
#include <iostream>

#include "winx/apple_id.hpp"
#include "winx/auth_session.hpp"
#include "winx/files.hpp"
#include "winx/sign_in.hpp"
#include "winx/text.hpp"

namespace winx::cli {
namespace {

using auth::AuthState;

int login_with_key(const AuthLoginOptions& options) {
    if (options.key_id.empty() || options.issuer_id.empty() || options.key_path.empty()) {
        std::cerr << "error: --key-id, --issuer-id and --key are required with --mode key\n";
        return 2;
    }
    std::cout << auth::api_key_warning() << '\n';
    if (!options.accept_warning && !confirm("Continue?")) return 1;

    const auto pem = read_text_file(to_wide(options.key_path));
    if (!pem) {
        std::cerr << "error: cannot read " << options.key_path << '\n';
        return 1;
    }
    try {
        engine::sign_in_with_api_key({options.key_id, options.issuer_id, *pem});
    } catch (const auth::ApiError& error) {
        std::cerr << "error: Apple rejected the key: " << error.what() << '\n';
        return 1;
    }
    std::cout << "Signed in. The key was imported into the Windows key store as non-exportable; "
                 "the .p8 file is no longer needed by WinXcode.\n";
    return 0;
}

int login_with_password(const AuthLoginOptions& options) {
    std::cout << auth::apple_id_warning() << '\n';
    if (!options.accept_warning && !confirm("I understand the risks. Continue?")) return 1;

    const std::string apple_id =
        options.apple_id.empty() ? prompt_line("Apple ID") : options.apple_id;
    std::string password = prompt_secret("Password");

    engine::AppleIdPrompts prompts;
    prompts.status = [](const std::string& message) { std::cout << message << '\n'; };
    prompts.verification_code = [](bool sms) {
        return prompt_line(sms ? "Code from the text message"
                               : "Verification code shown on your Apple device (or 'sms' for a "
                                 "text)");
    };
    prompts.choose_team = [](const std::vector<auth::Team>& teams) -> std::size_t {
        for (std::size_t i = 0; i < teams.size(); ++i) {
            std::cout << std::format("  {}. {} ({}){}\n", i + 1, teams[i].name, teams[i].id,
                                     teams[i].free ? " [free]" : "");
        }
        const int index = std::atoi(prompt_line("Team number").c_str());
        return index >= 1 ? static_cast<std::size_t>(index - 1) : teams.size();
    };

    const AuthState state = engine::sign_in_with_apple_id(
        apple_id, std::move(password), options.anisette_url, options.team_id, prompts);
    std::cout << std::format("Signed in as {} on team {} ({}).\n", state.apple_id, state.team_name,
                             state.team_id);
    return 0;
}

}  // namespace

std::string prompt_line(const std::string& label) {
    std::cout << label << ": " << std::flush;
    std::string line;
    std::getline(std::cin, line);
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    return line;
}

std::string prompt_secret(const std::string& label) {
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool console = GetConsoleMode(input, &mode) != FALSE;
    if (console) SetConsoleMode(input, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    std::string secret = prompt_line(label);
    if (console) {
        SetConsoleMode(input, mode);
        std::cout << '\n';
    }
    return secret;
}

bool confirm(const std::string& question) {
    const std::string answer = prompt_line(question + " Type 'yes' to proceed");
    return answer == "yes" || answer == "YES" || answer == "Yes";
}

int run_auth_login(const AuthLoginOptions& options) {
    try {
        if (options.mode == "key") return login_with_key(options);
        if (options.mode == "password") return login_with_password(options);
        std::cerr << "error: --mode must be 'key' or 'password'\n";
        return 2;
    } catch (const auth::AppleIdError& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const auth::KeyError& error) {
        std::cerr << "error: " << error.what() << '\n';
    }
    return 1;
}

int run_auth_status() {
    const auth::AuthStore store(app_data_dir());
    const AuthState state = store.load();
    switch (state.mode) {
        case AuthState::Mode::None:
            std::cout << "Not signed in.\n";
            return 1;
        case AuthState::Mode::ApiKey:
            std::cout << "Signed in with an App Store Connect API key\n"
                      << "  Key ID:    " << state.key_id << '\n'
                      << "  Issuer ID: " << state.issuer_id << '\n';
            return 0;
        case AuthState::Mode::AppleId: {
            std::cout << "Signed in with an Apple ID (unofficial protocol)\n"
                      << "  Apple ID: " << state.apple_id << '\n'
                      << "  Team:     " << state.team_name << " (" << state.team_id << ")\n";
            const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            if (state.token_expiry_ms != 0 && state.token_expiry_ms < now) {
                std::cout << "  The session has expired; run `winx auth login` again.\n";
            }
            return 0;
        }
    }
    return 0;
}

int run_auth_logout() {
    engine::sign_out();
    std::cout << "Signed out. Stored credentials were removed; signing certificates were kept.\n";
    return 0;
}

}  // namespace winx::cli
