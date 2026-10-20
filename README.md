<div align="center">

<!-- Logo: replace with docs/assets/logo.png (256x256) once available -->
<img src="docs/assets/logo.png" alt="WinXcode logo" width="128" height="128">

# WinXcode

**Build, sign and install iOS apps natively on Windows. No Mac, no WSL, no VM.**

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?logo=windows&logoColor=white)](#requirements)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)](CMakeLists.txt)
[![CMake](https://img.shields.io/badge/CMake-3.25%2B-064F8C?logo=cmake&logoColor=white)](CMakePresets.json)
[![Swift](https://img.shields.io/badge/Swift-6.4%2B-F05138?logo=swift&logoColor=white)](https://www.swift.org/install/windows/)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](CMakeLists.txt)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

[Quick start](#quick-start) · [Commands](#commands) · [Sign-in modes](#two-ways-to-sign-in) · [Roadmap](#roadmap) · [Contributing](CONTRIBUTING.md)

</div>

---

## Why WinXcode?

Shipping an iPhone app has always meant owning a Mac. **WinXcode** is a native Windows toolchain and
IDE, modelled on [xtool](https://github.com/xtool-org/xtool), that takes a SwiftUI project from
`winx new` to running on your iPhone over USB. It builds with Swift for Windows, signs with a C++20 code-signing
engine and installs through Apple Mobile Device Service. It runs on plain Windows, with no WSL,
virtual machine or POSIX layer.

## Key features

- **100% native Windows.** Written in C++20 with MSVC. It runs without WSL, Cygwin or a VM.
- **One-command dev loop.** `winx dev` builds, signs and installs on the attached iPhone.
- **Built-in code signing.** It signs `.app` bundles and Mach-O binaries, verifies signatures and supports ad-hoc signing.
- **Two sign-in modes.** Use an official App Store Connect API key, or an Apple ID with a free account.
- **Automatic provisioning.** `winx ds provision` registers the device and creates the bundle ID, certificate and profile.
- **iOS SDK from your own Xcode.** `winx sdk install Xcode.xip` builds the SDK bundle from your copy of Xcode.
- **Direct device access.** It handles usbmux, lockdown and pairing records, and can list apps, stream the live device log and toggle Developer Mode.
- **USB or Wi-Fi.** After `winx device wifi --on` over USB once, every command also works with the phone on the same Wi-Fi network.
- **`.ipa` export.** `winx export` packs the signed app as an `.ipa`, and `winx install` accepts one.
- **Lightweight IDE.** `winxcode.exe` is a Dear ImGui editor with Swift syntax highlighting and a Run button.
- **Secure key storage.** `.p8` keys go into the Windows key store as non-exportable, and passwords are never saved.

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 with **Desktop development with C++** (MSVC, CMake, Windows SDK)
- Git (CMake fetches the pinned dependencies at configure time)
- Apple Devices or iTunes, which installs **Apple Mobile Device Service**
- To build apps: [Swift for Windows](https://www.swift.org/install/windows/) 6.4 or newer, and your own `Xcode.xip` from [developer.apple.com](https://developer.apple.com/download/)
- To sign and install: an Apple Developer account and an iPhone with **Developer Mode** turned on

## Installation

From a **Developer PowerShell for VS 2022** prompt:

```powershell
git clone https://github.com/theclasscoder-eng/WinXcode.git
cd WinXcode
cmake --preset vs2022-x64
cmake --build build --config Release
ctest --test-dir build -C Release
```

The build writes these files to `build\bin\Release`:

| Binary | What it is |
|---|---|
| `winx.exe` | Command-line toolchain |
| `winxcode.exe` | IDE |
| `winx-ld64-shim.exe` | Linker shim, copied into the SDK bundle |

## Quick start

```powershell
winx setup                                  # what is installed and what is missing
winx auth login --mode key --key-id <ID> --issuer-id <ISSUER> --key AuthKey_<ID>.p8
winx sdk install C:\Downloads\Xcode.xip     # builds the iOS SDK bundle from your Xcode
winx new Hello
cd Hello
winx dev                                    # build, sign, install on the attached iPhone
```

You can also open the folder in the IDE with `winxcode.exe Hello` and press **Run**.

## Commands

| Command | Purpose |
|---|---|
| `winx setup` | Check toolchain, SDK, sign-in, Apple Mobile Device Service and device |
| `winx devices [--watch] [-v] [--paired]` | Attached devices; live attach/detach; pairing records |
| `winx auth login --mode key\|password` | Sign in with an API key (official) or an Apple ID (unofficial) |
| `winx auth status`, `winx auth logout` | Show or remove the stored sign-in |
| `winx ds devices\|identifiers\|certificates\|profiles\|teams` | List developer account resources |
| `winx ds provision --bundle-id <id>` | Ensure device, bundle ID, certificate and profile exist |
| `winx sdk install <Xcode.xip>`, `winx sdk status` | Manage the iOS SDK bundle |
| `winx new <Name>` | Create a SwiftUI project (SwiftPM package + `xtool.yml`) |
| `winx build`, `winx dev` | Build only; or build, sign and install |
| `winx export [-o App.ipa] [--unsigned]` | Build, sign and pack the app as an `.ipa` |
| `winx sign <App.app> [--verify] [--adhoc]` | Code-sign a bundle or Mach-O, or check a signature |
| `winx install <App.app\|App.ipa>`, `winx uninstall <bundle-id>` | Install or remove an app |
| `winx device apps\|log\|devmode [--reveal]` | Installed apps, live device log, Developer Mode |
| `winx device wifi [--on\|--off]` | Let the device be reached over Wi-Fi as well as USB |

### Working over Wi-Fi

Plug the phone in once, then run `winx device wifi --on`. While the phone is awake and on the
same network as the PC, `winx devices` lists it as `Wi-Fi`, and `winx dev`, `winx install` and the
`winx device` commands use that connection. USB is still preferred whenever the cable is plugged
in. Run `winx device wifi --off` to stop.

## Two ways to sign in

| Mode | Flag | Account | Status |
|---|---|---|---|
| **App Store Connect API key** | `--mode key` | Paid Apple Developer Program | Apple's documented API. The `.p8` key is stored as non-exportable in the Windows key store. |
| **Apple ID and password** | `--mode password` | Free or paid | Unofficial. It uses the protocol Xcode uses, reconstructed by third parties as in xtool. |

> [!WARNING]
> Apple does not sanction **Apple ID sign-in**. It depends on a third-party "anisette" server for
> machine-identity headers, and Apple may lock the account. **Use a burner account.** WinXcode uses
> the password once and never stores it. The source is open, so you can check this yourself.

## Project layout

```
apps/win_ide/            winxcode.exe: Dear ImGui IDE
tools/winx/              winx.exe: command-line front end
tools/ld64_shim/         linker shim used inside the SDK bundle
libs/winx_core/          plist, DER, crypto, HTTP, sockets, files
libs/win_device_transport/  usbmux, lockdown, TLS, pairing, device services
libs/win_dev_auth/       API keys, Apple ID (GrandSlam/SRP), anisette, provisioning
libs/win_codesign/       Mach-O and bundle code signing
libs/win_build_driver/   Swift build orchestration
libs/winx_engine/        end-to-end pipeline used by the CLI and IDE
tests/                   Catch2 tests with fake device and fake Swift toolchain
```

## Roadmap

- [x] Native usbmux / lockdown device transport and pairing records
- [x] App Store Connect API key sign-in
- [x] Apple ID sign-in (unofficial, burner account recommended)
- [x] Automatic provisioning (device, bundle ID, certificate, profile)
- [x] iOS SDK bundle built from a user-supplied `Xcode.xip`
- [x] Code signing and verification for bundles and Mach-O binaries
- [x] `winx dev` one-command build → sign → install loop
- [x] ImGui IDE with Swift highlighting and Run
- [x] Wi-Fi device connections (`winx device wifi --on`)
- [x] `.ipa` export, development-signed or unsigned (`winx export`, **Product > Export .ipa**)
- [ ] Prebuilt binaries and a Windows installer (winget / Scoop)
- [ ] LLDB debugging from the IDE
- [ ] SourceKit-LSP code completion in the IDE
- [ ] App extensions and multi-target projects
- [ ] Ad Hoc and App Store distribution signing for exported `.ipa` files

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, and look for issues
labelled [`good first issue`](https://github.com/theclasscoder-eng/WinXcode/labels/good%20first%20issue).

## License

WinXcode is released under the [MIT License](LICENSE). Contributions are accepted under the same license.

## Acknowledgements

- [xtool](https://github.com/xtool-org/xtool): the design WinXcode is modelled on
- [Dear ImGui](https://github.com/ocornut/imgui), [ImGuiColorTextEdit](https://github.com/goossens/ImGuiColorTextEdit), [CLI11](https://github.com/CLIUtils/CLI11), [nlohmann/json](https://github.com/nlohmann/json), [yaml-cpp](https://github.com/jbeder/yaml-cpp), [miniz](https://github.com/richgel999/miniz), [xz](https://github.com/tukaani-project/xz), [Catch2](https://github.com/catchorg/Catch2)

<sub>WinXcode is not affiliated with or endorsed by Apple Inc. Xcode, iPhone and iOS are trademarks of Apple Inc.</sub>
