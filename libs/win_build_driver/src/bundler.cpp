#include "winx/bundler.hpp"

#include <windows.h>

#include <wincodec.h>
#include <wrl/client.h>

#include <algorithm>
#include <format>

#include "winx/files.hpp"
#include "winx/text.hpp"

namespace winx::build {
namespace {

namespace fs = std::filesystem;
using Microsoft::WRL::ComPtr;

void check(HRESULT result, const char* what) {
    if (FAILED(result)) {
        throw ProjectError(std::format("{} failed (0x{:08X})", what, static_cast<unsigned>(result)));
    }
}

ComPtr<IWICImagingFactory> imaging_factory() {
    // S_FALSE and RPC_E_CHANGED_MODE both mean COM is already usable here.
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ComPtr<IWICImagingFactory> factory;
    check(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                           IID_PPV_ARGS(&factory)),
          "starting the Windows Imaging Component");
    return factory;
}

ComPtr<IWICBitmapFrameDecode> first_frame(IWICImagingFactory& factory, const fs::path& path) {
    ComPtr<IWICBitmapDecoder> decoder;
    if (FAILED(factory.CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                                                 WICDecodeMetadataCacheOnDemand, &decoder))) {
        throw ProjectError("cannot read the image " + to_utf8(path.wstring()));
    }
    ComPtr<IWICBitmapFrameDecode> frame;
    check(decoder->GetFrame(0, &frame), "decoding the image");
    return frame;
}

void encode_png(IWICImagingFactory& factory, IWICBitmapSource& source, const fs::path& destination,
                unsigned width, unsigned height) {
    if (destination.has_parent_path()) fs::create_directories(destination.parent_path());
    ComPtr<IWICStream> stream;
    check(factory.CreateStream(&stream), "creating an image stream");
    check(stream->InitializeFromFilename(destination.c_str(), GENERIC_WRITE), "opening the PNG");
    ComPtr<IWICBitmapEncoder> encoder;
    check(factory.CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder), "creating the encoder");
    check(encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache), "starting the encoder");
    ComPtr<IWICBitmapFrameEncode> frame;
    check(encoder->CreateNewFrame(&frame, nullptr), "creating a PNG frame");
    check(frame->Initialize(nullptr), "starting the PNG frame");
    check(frame->SetSize(width, height), "sizing the PNG");
    WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
    check(frame->SetPixelFormat(&format), "choosing the pixel format");
    check(frame->WriteSource(&source, nullptr), "writing the PNG");
    check(frame->Commit(), "finishing the PNG frame");
    check(encoder->Commit(), "finishing the PNG");
}

void copy_tree(const fs::path& from, const fs::path& to) {
    fs::create_directories(to.parent_path());
    fs::copy(from, to, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
}

bool has_extension(const fs::path& path, std::wstring_view extension) {
    std::wstring actual = path.extension().wstring();
    std::transform(actual.begin(), actual.end(), actual.begin(), ::towlower);
    return actual == extension;
}

struct IconVariant {
    const char* base;    // name listed in Info.plist
    const char* suffix;  // scale and idiom
    unsigned pixels;
    bool ipad;
};

constexpr IconVariant kIcons[] = {
    {"AppIcon60x60", "@2x", 120, false},
    {"AppIcon60x60", "@3x", 180, false},
    {"AppIcon76x76", "@2x~ipad", 152, true},
    {"AppIcon83.5x83.5", "@2x~ipad", 167, true},
};

}  // namespace

void scale_png(const fs::path& source, const fs::path& destination, unsigned size) {
    const ComPtr<IWICImagingFactory> factory = imaging_factory();
    const ComPtr<IWICBitmapFrameDecode> frame = first_frame(*factory.Get(), source);
    ComPtr<IWICFormatConverter> converter;
    check(factory->CreateFormatConverter(&converter), "creating a format converter");
    check(converter->Initialize(frame.Get(), GUID_WICPixelFormat32bppBGRA, WICBitmapDitherTypeNone,
                                nullptr, 0.0, WICBitmapPaletteTypeCustom),
          "converting the image");
    ComPtr<IWICBitmapScaler> scaler;
    check(factory->CreateBitmapScaler(&scaler), "creating a scaler");
    check(scaler->Initialize(converter.Get(), size, size, WICBitmapInterpolationModeFant),
          "scaling the image");
    encode_png(*factory.Get(), *scaler.Get(), destination, size, size);
}

void write_png(const fs::path& destination, unsigned width, unsigned height,
               std::span<const std::uint8_t> bgra) {
    if (bgra.size() != static_cast<std::size_t>(width) * height * 4) {
        throw ProjectError("pixel data does not match the image size");
    }
    const ComPtr<IWICImagingFactory> factory = imaging_factory();
    ComPtr<IWICBitmap> bitmap;
    check(factory->CreateBitmapFromMemory(width, height, GUID_WICPixelFormat32bppBGRA, width * 4,
                                          static_cast<UINT>(bgra.size()),
                                          const_cast<BYTE*>(bgra.data()), &bitmap),
          "creating a bitmap");
    encode_png(*factory.Get(), *bitmap.Get(), destination, width, height);
}

std::pair<unsigned, unsigned> image_size(const fs::path& path) {
    const ComPtr<IWICImagingFactory> factory = imaging_factory();
    const ComPtr<IWICBitmapFrameDecode> frame = first_frame(*factory.Get(), path);
    UINT width = 0;
    UINT height = 0;
    check(frame->GetSize(&width, &height), "reading the image size");
    return {width, height};
}

plist::Value make_info_plist(const BundleRequest& request, const std::string& bundle_id,
                             const plist::Value* user_plist) {
    const std::string minimum =
        request.deployment_target.empty() ? "17.0" : request.deployment_target;
    plist::Dict info{
        {"CFBundleInfoDictionaryVersion", "6.0"},
        {"CFBundleDevelopmentRegion", "en"},
        {"CFBundleIdentifier", bundle_id},
        {"CFBundleName", request.product},
        {"CFBundleDisplayName", request.product},
        {"CFBundleExecutable", request.product},
        {"CFBundlePackageType", "APPL"},
        {"CFBundleVersion", "1"},
        {"CFBundleShortVersionString", "1.0.0"},
        {"CFBundleSupportedPlatforms", plist::Array{"iPhoneOS"}},
        {"MinimumOSVersion", minimum},
        {"LSRequiresIPhoneOS", true},
        {"UIDeviceFamily", plist::Array{1, 2}},
        {"UIRequiredDeviceCapabilities", plist::Array{"arm64"}},
        // An empty dictionary opts in to full-screen layout without a storyboard.
        {"UILaunchScreen", plist::Dict{}},
        {"UISupportedInterfaceOrientations",
         plist::Array{"UIInterfaceOrientationPortrait", "UIInterfaceOrientationLandscapeLeft",
                      "UIInterfaceOrientationLandscapeRight"}},
        {"UISupportedInterfaceOrientations~ipad",
         plist::Array{"UIInterfaceOrientationPortrait", "UIInterfaceOrientationPortraitUpsideDown",
                      "UIInterfaceOrientationLandscapeLeft",
                      "UIInterfaceOrientationLandscapeRight"}},
        {"DTPlatformName", "iphoneos"},
    };
    if (!request.sdk_version.empty()) {
        info.set("DTPlatformVersion", request.sdk_version);
        info.set("DTSDKName", "iphoneos" + request.sdk_version);
    }
    if (user_plist && user_plist->is<plist::Dict>()) {
        for (const auto& [key, value] : user_plist->as_dict().items()) info.set(key, value);
    }
    // These two must agree with what was built and what will be signed.
    info.set("CFBundleExecutable", request.product);
    info.set("CFBundleIdentifier", bundle_id);
    return info;
}

BundleResult assemble_bundle(const BundleRequest& request) {
    BundleResult result;
    result.bundle_id = request.config.bundle_id_for(request.product);
    result.bundle = request.output_dir / to_wide(request.product + ".app");

    std::error_code ec;
    fs::remove_all(result.bundle, ec);
    fs::create_directories(result.bundle);
    fs::copy_file(request.executable, result.bundle / to_wide(request.product),
                  fs::copy_options::overwrite_existing);
    write_text_file(result.bundle / L"PkgInfo", "APPL????");

    plist::Value user_plist;
    if (!request.config.info_path.empty()) {
        const fs::path path = request.project_dir / to_wide(request.config.info_path);
        if (!fs::is_regular_file(path, ec)) {
            throw ProjectError("infoPath does not exist: " + request.config.info_path);
        }
        user_plist = plist::load_file(path);
    }
    plist::Value info =
        make_info_plist(request, result.bundle_id, user_plist.is_null() ? nullptr : &user_plist);
    plist::Dict& info_dict = *info.get_if<plist::Dict>();

    if (!request.config.icon_path.empty()) {
        const fs::path icon = request.project_dir / to_wide(request.config.icon_path);
        if (!fs::is_regular_file(icon, ec)) {
            throw ProjectError("iconPath does not exist: " + request.config.icon_path);
        }
        const auto [width, height] = image_size(icon);
        if (width != height) result.warnings.emplace_back("the app icon is not square; it will be stretched");
        if (width < 180) result.warnings.emplace_back("the app icon is smaller than 180 pixels and will look soft");
        for (const IconVariant& variant : kIcons) {
            scale_png(icon, result.bundle / to_wide(std::string(variant.base) + variant.suffix + ".png"),
                      variant.pixels);
        }
        const auto icon_entry = [](plist::Array files) {
            return plist::Dict{{"CFBundlePrimaryIcon",
                                plist::Dict{{"CFBundleIconFiles", std::move(files)},
                                            {"CFBundleIconName", "AppIcon"}}}};
        };
        info_dict.set("CFBundleIcons", icon_entry(plist::Array{"AppIcon60x60"}));
        info_dict.set("CFBundleIcons~ipad",
                      icon_entry(plist::Array{"AppIcon60x60", "AppIcon76x76", "AppIcon83.5x83.5"}));
    }
    write_file(result.bundle / L"Info.plist", plist::to_binary(info));

    // Resources listed in xtool.yml go to the bundle root.
    for (const std::string& resource : request.config.resources) {
        const fs::path source = request.project_dir / to_wide(resource);
        if (!fs::exists(source, ec)) {
            throw ProjectError("resource does not exist: " + resource);
        }
        copy_tree(source, result.bundle / source.filename());
    }

    // SwiftPM resource bundles and dynamic products built alongside the app.
    if (fs::is_directory(request.bin_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(request.bin_dir, ec)) {
            const fs::path& path = entry.path();
            if (entry.is_directory() && has_extension(path, L".bundle")) {
                copy_tree(path, result.bundle / path.filename());
            } else if (entry.is_directory() && has_extension(path, L".framework")) {
                copy_tree(path, result.bundle / L"Frameworks" / path.filename());
            } else if (entry.is_regular_file() && has_extension(path, L".dylib")) {
                copy_tree(path, result.bundle / L"Frameworks" / path.filename());
            }
        }
    }

    if (!request.config.extensions.empty()) {
        result.warnings.emplace_back(
            "app extensions listed in xtool.yml are not built yet and were left out of the bundle");
    }
    return result;
}

}  // namespace winx::build
