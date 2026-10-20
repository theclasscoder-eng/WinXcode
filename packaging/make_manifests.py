"""Writes the Scoop and winget manifests for a release zip.

Run by .github/workflows/release.yml after `cpack`:

    python packaging/make_manifests.py --version 0.1.0 \
        --zip build/WinXcode-0.1.0-win-x64.zip --out build/manifests

The Scoop manifest can be installed straight from the release
(`scoop install <url of winxcode.json>`) or copied into a bucket. The winget
manifests go into a pull request to microsoft/winget-pkgs under
manifests/t/theclasscoder/WinXcode/<version>/.
"""

import argparse
import hashlib
import json
import pathlib

REPOSITORY = "https://github.com/theclasscoder-eng/WinXcode"
PACKAGE_ID = "theclasscoder.WinXcode"
DESCRIPTION = "Build, sign and install iOS apps natively on Windows."
WINGET_SCHEMA = "1.6.0"


def release_url(version: str) -> str:
    return f"{REPOSITORY}/releases/download/v{version}/WinXcode-{version}-win-x64.zip"


def scoop_manifest(version: str, sha256: str) -> dict:
    return {
        "version": version,
        "description": DESCRIPTION,
        "homepage": REPOSITORY,
        "license": "MIT",
        "notes": "Run `winx setup` to see what else is needed (Swift, the iOS SDK, sign-in).",
        "architecture": {"64bit": {"url": release_url(version), "hash": sha256}},
        "bin": "winx.exe",
        "shortcuts": [["winxcode.exe", "WinXcode"]],
        "checkver": {"github": REPOSITORY},
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": f"{REPOSITORY}/releases/download/v$version/WinXcode-$version-win-x64.zip"
                }
            }
        },
    }


def winget_manifests(version: str, sha256: str) -> dict:
    header = f"PackageIdentifier: {PACKAGE_ID}\nPackageVersion: {version}\n"
    footer = f"ManifestVersion: {WINGET_SCHEMA}\n"
    return {
        f"{PACKAGE_ID}.yaml": header + "DefaultLocale: en-US\nManifestType: version\n" + footer,
        f"{PACKAGE_ID}.installer.yaml": header
        + "InstallerType: zip\n"
        + "NestedInstallerType: portable\n"
        + "NestedInstallerFiles:\n"
        + "  - RelativeFilePath: winx.exe\n"
        + "    PortableCommandAlias: winx\n"
        + "  - RelativeFilePath: winxcode.exe\n"
        + "    PortableCommandAlias: winxcode\n"
        + "Installers:\n"
        + "  - Architecture: x64\n"
        + f"    InstallerUrl: {release_url(version)}\n"
        + f"    InstallerSha256: {sha256.upper()}\n"
        + "ManifestType: installer\n"
        + footer,
        f"{PACKAGE_ID}.locale.en-US.yaml": header
        + "PackageLocale: en-US\n"
        + "Publisher: theclasscoder-eng\n"
        + f"PublisherUrl: {REPOSITORY}\n"
        + "PackageName: WinXcode\n"
        + f"PackageUrl: {REPOSITORY}\n"
        + "License: MIT\n"
        + f"LicenseUrl: {REPOSITORY}/blob/main/LICENSE\n"
        + f"ShortDescription: {DESCRIPTION}\n"
        + "Tags:\n  - ios\n  - iphone\n  - swift\n  - xcode\n"
        + "ManifestType: defaultLocale\n"
        + footer,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version, without the v")
    parser.add_argument("--zip", required=True, type=pathlib.Path, help="the cpack zip")
    parser.add_argument("--out", required=True, type=pathlib.Path, help="output directory")
    args = parser.parse_args()

    sha256 = hashlib.sha256(args.zip.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    scoop = args.out / "winxcode.json"
    scoop.write_text(json.dumps(scoop_manifest(args.version, sha256), indent=4) + "\n")
    winget = args.out / "winget"
    winget.mkdir(exist_ok=True)
    for name, text in winget_manifests(args.version, sha256).items():
        (winget / name).write_text(text, newline="\n")
    print(f"sha256 {sha256}")
    print(f"wrote {scoop} and {len(list(winget.iterdir()))} winget manifests in {winget}")


if __name__ == "__main__":
    main()
