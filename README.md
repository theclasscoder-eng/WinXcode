# WinXcode

A native Windows toolchain and IDE for building, signing and installing iOS apps, modelled on
[xtool](https://github.com/xtool-org/xtool). No WSL, virtual machine or POSIX layer.

- Windows 10/11 x64
- Visual Studio 2022 with "Desktop development with C++" (MSVC, CMake, Windows SDK)
- Git (CMake fetches the pinned dependencies at configure time)
- Apple Devices or iTunes, which installs Apple Mobile Device Service
- To build apps: [Swift for Windows](https://www.swift.org/install/windows/) 6.4 or newer, and
  your own `Xcode.xip` from developer.apple.com
- To sign and install: an Apple Developer account and an iPhone with Developer Mode on

## Build

From a "Developer PowerShell for VS 2022" prompt:

```powershell
cmake --preset vs2022-x64
cmake --build build --config Release
ctest --test-dir build -C Release
```

Outputs land in `build\bin\Release`: `winx.exe` (command line), `winxcode.exe` (IDE) and
`winx-ld64-shim.exe` (copied into the SDK bundle).

## Quick start

```powershell
winx setup                                  # what is installed and what is missing
winx auth login --mode key --key-id <ID> --issuer-id <ISSUER> --key AuthKey_<ID>.p8
winx sdk install C:\Downloads\Xcode.xip     # builds the iOS SDK bundle from your Xcode
winx new Hello
cd Hello
winx dev                                    # build, sign, install on the attached iPhone
```

Or open the folder in the IDE: `winxcode.exe Hello`, then press Run.

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
| `winx sign <App.app> [--verify] [--adhoc]` | Code-sign a bundle or Mach-O, or check a signature |
| `winx install <App.app>`, `winx uninstall <bundle-id>` | Install or remove an app |
| `winx device apps\|log\|devmode [--reveal]` | Installed apps, live device log, Developer Mode |

## Two ways to sign in

- **App Store Connect API key** — Apple's documented API. Needs a paid Apple Developer Program
  membership. The `.p8` key is imported into the Windows key store as non-exportable.
- **Apple ID and password** — the protocol Xcode uses, reconstructed by third parties, as in
  xtool. It works with free accounts but is not sanctioned by Apple, relies on a third-party
  "anisette" server for machine-identity headers, and carries a risk of the account being. Currently, it is recommended to use a burner account as Apple does not like this and can lock your account.
The password is used once and never stored. This is an open source project so you can verify this.

