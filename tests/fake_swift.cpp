// A stand-in for swift.exe, used by the build-driver tests. It understands just
// enough of the command line WinXcode produces, and is steered through
// environment variables:
//
//   WINX_FAKE_SWIFT_VERSION  version to report (default 6.4)
//   WINX_FAKE_SWIFT_DUMP     file whose contents answer `package dump-package`
//   WINX_FAKE_SWIFT_PRODUCT  file copied to the bin directory as the product
//   WINX_FAKE_SWIFT_FAIL     when "1", print diagnostics and exit 1
//   WINX_FAKE_SWIFT_LOG      file that receives one line per invocation

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::string env(const char* name, const std::string& fallback = {}) {
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) return fallback;
    std::string text(value);
    std::free(value);
    return text;
}

std::string option(const std::vector<std::string>& arguments, const std::string& name) {
    for (std::size_t i = 0; i + 1 < arguments.size(); ++i) {
        if (arguments[i] == name) return arguments[i + 1];
    }
    return {};
}

bool has(const std::vector<std::string>& arguments, const std::string& name) {
    for (const std::string& argument : arguments) {
        if (argument == name) return true;
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    const std::vector<std::string> arguments(argv + 1, argv + argc);
    if (const std::string log = env("WINX_FAKE_SWIFT_LOG"); !log.empty()) {
        std::ofstream out(log, std::ios::app);
        for (const std::string& argument : arguments) out << argument << '\t';
        out << '\n';
    }

    if (has(arguments, "--version")) {
        std::cout << "Swift version " << env("WINX_FAKE_SWIFT_VERSION", "6.4")
                  << " (swift-fake-RELEASE)\nTarget: x86_64-unknown-windows-msvc\n";
        return 0;
    }
    if (arguments.size() >= 2 && arguments[0] == "package" && arguments[1] == "dump-package") {
        std::ifstream dump(env("WINX_FAKE_SWIFT_DUMP"));
        if (!dump) {
            std::cerr << "error: no such manifest\n";
            return 1;
        }
        // A real manifest compile can print warnings ahead of the JSON.
        std::cout << "warning: this line precedes the JSON\n" << dump.rdbuf();
        return 0;
    }
    if (!arguments.empty() && arguments[0] == "build") {
        const std::filesystem::path bin = std::filesystem::path(option(arguments, "--scratch-path")) /
                                          option(arguments, "--swift-sdk") /
                                          option(arguments, "--configuration");
        if (has(arguments, "--show-bin-path")) {
            std::cout << bin.string() << '\n';
            return 0;
        }
        std::cout << "Building for debugging...\n";
        if (env("WINX_FAKE_SWIFT_FAIL") == "1") {
            std::cout << "C:\\src\\Hello\\Sources\\Hello\\ContentView.swift:7:13: error: cannot find "
                         "'Texty' in scope\n"
                      << "            Texty(\"Hello\")\n"
                      << "            ^~~~~\n"
                      << "C:\\src\\Hello\\Sources\\Hello\\HelloApp.swift:3:1: warning: unused "
                         "variable\n"
                      << "error: fatalError\n";
            return 1;
        }
        std::filesystem::create_directories(bin);
        std::error_code ec;
        std::filesystem::copy_file(env("WINX_FAKE_SWIFT_PRODUCT"), bin / option(arguments, "--product"),
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            std::cerr << "error: fake product missing\n";
            return 1;
        }
        std::cout << "[1/1] Linking " << option(arguments, "--product") << "\nBuild complete!\n";
        return 0;
    }
    std::cerr << "fake swift: unsupported invocation\n";
    return 64;
}
