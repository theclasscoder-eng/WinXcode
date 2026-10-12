# Contributing to WinXcode

Thanks for helping make iOS development on Windows possible. This guide covers reporting bugs,
suggesting features and getting a pull request merged.

## 🌱 New here? Start with a good first issue

Issues labelled [`good first issue`](https://github.com/theclasscoder-eng/WinXcode/labels/good%20first%20issue)
are small and well scoped, and each one says which files to change. To claim one, comment on the
issue so nobody else starts the same work. If you get stuck, ask on the issue.

Other useful labels: `help wanted`, `bug`, `enhancement`, `docs`, `device-transport`, `codesign`, `auth`, `ide`.

## 🐛 Reporting bugs

1. Search [existing issues](https://github.com/theclasscoder-eng/WinXcode/issues) to check that the bug has not been reported yet.
2. Open a new issue using the **Bug report** template.
3. Include the output of `winx setup`, the exact command you ran and the full error output.

> [!CAUTION]
> Remove secrets before posting: API key IDs, issuer IDs, `.p8` contents, Apple IDs, device UDIDs
> and pairing records.

For security vulnerabilities, do **not** open a public issue. Contact the maintainers privately
through [GitHub Security Advisories](https://github.com/theclasscoder-eng/WinXcode/security/advisories/new).

## 💡 Suggesting features

Open an issue labelled `enhancement` that describes:

- The problem you are trying to solve, not only the solution
- How you would expect it to work (for example, a sample `winx` command)
- Any prior art, such as how xtool or Xcode handles it

Check the [Roadmap](README.md#roadmap) first, because the feature may already be planned.

## 🛠️ Development setup

Requirements: Windows 10/11 x64 and Visual Studio 2022 with **Desktop development with C++**.
Swift for Windows, an iPhone and an Apple account are only needed for end-to-end testing. The unit
tests use a fake device and a fake Swift toolchain.

```powershell
git clone https://github.com/<you>/WinXcode.git
cd WinXcode
cmake --preset vs2022-x64
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

## 🔀 Submitting a pull request

1. Fork the repository and create a branch from `main`, such as `fix/usbmux-timeout` or `feat/wifi-devices`.
2. Keep each PR focused on one change. Small PRs get reviewed sooner.
3. Follow the existing style:
   - C++20 that compiles cleanly at MSVC `/W4 /permissive-`
   - Code goes in the library that owns it (`winx_core`, `win_device_transport`, `win_dev_auth`, `win_codesign`, `win_build_driver`, `winx_engine`)
   - Match the naming, comment density and idioms of the surrounding code
4. Add or update tests in `tests/`. Use `fake_device` and `fake_swift` so tests do not need hardware.
5. Make sure `ctest` passes locally.
6. Update `README.md` when you change a command, flag or requirement.
7. Open the PR, fill in what changed and why, and link the issue (`Closes #123`).

### Commit messages

Write short, imperative subject lines, for example `Add Wi-Fi device discovery` or
`Fix lockdown TLS handshake on reconnect`. Use the body to explain why the change is needed.

## 🤝 Code of conduct

Be respectful, patient and constructive. Harassment and personal attacks are not tolerated.
