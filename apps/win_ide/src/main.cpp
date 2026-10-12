// WinXcode IDE: a Win32 window with a Direct3D 11 swap chain, hosting a Dear
// ImGui user interface.

#include <windows.h>

#include <d3d11.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <wrl/client.h>

#include <filesystem>
#include <string>

#include "ide_app.hpp"
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "winx/files.hpp"
#include "winx/text.hpp"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND window, UINT message, WPARAM wparam,
                                                             LPARAM lparam);

namespace {

using Microsoft::WRL::ComPtr;

ComPtr<ID3D11Device> g_device;
ComPtr<ID3D11DeviceContext> g_context;
ComPtr<IDXGISwapChain> g_swap_chain;
ComPtr<ID3D11RenderTargetView> g_target;
UINT g_resize_width = 0;
UINT g_resize_height = 0;
winx::ide::IdeApp* g_app = nullptr;

void create_render_target() {
    ComPtr<ID3D11Texture2D> back_buffer;
    if (SUCCEEDED(g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer)))) {
        g_device->CreateRenderTargetView(back_buffer.Get(), nullptr, &g_target);
    }
}

bool create_device(HWND window) {
    DXGI_SWAP_CHAIN_DESC description{};
    description.BufferCount = 2;
    description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    description.BufferDesc.RefreshRate.Numerator = 60;
    description.BufferDesc.RefreshRate.Denominator = 1;
    description.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    description.OutputWindow = window;
    description.SampleDesc.Count = 1;
    description.Windowed = TRUE;
    description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL level{};
    HRESULT result = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &description,
        &g_swap_chain, &g_device, &level, &g_context);
    if (result == DXGI_ERROR_UNSUPPORTED) {
        // No usable GPU (remote sessions, some VMs): fall back to the software rasterizer.
        result = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &description,
            &g_swap_chain, &g_device, &level, &g_context);
    }
    if (FAILED(result)) return false;
    create_render_target();
    return true;
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(window, message, wparam, lparam)) return TRUE;
    switch (message) {
        case WM_SIZE:
            if (wparam != SIZE_MINIMIZED) {
                g_resize_width = LOWORD(lparam);
                g_resize_height = HIWORD(lparam);
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wparam & 0xFFF0) == SC_KEYMENU) return 0;  // no Alt menu beep
            break;
        case WM_CLOSE:
            // Let the app ask about unsaved files before the window goes away.
            if (g_app) {
                g_app->request_close();
                return 0;
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

std::string first_existing_font(std::initializer_list<const wchar_t*> names) {
    wchar_t windows[MAX_PATH];
    GetWindowsDirectoryW(windows, MAX_PATH);
    for (const wchar_t* name : names) {
        const std::filesystem::path path = std::filesystem::path(windows) / L"Fonts" / name;
        std::error_code ec;
        if (std::filesystem::is_regular_file(path, ec)) return winx::to_utf8(path.wstring());
    }
    return {};
}

ImFont* load_font(const std::string& path, float size) {
    ImGuiIO& io = ImGui::GetIO();
    if (path.empty()) return io.Fonts->AddFontDefault();
    // Latin, punctuation and the Cyrillic and Greek blocks cover typical source and device names.
    static const ImWchar ranges[] = {0x0020, 0x00FF, 0x0100, 0x024F, 0x0370, 0x03FF,
                                     0x0400, 0x04FF, 0x2000, 0x206F, 0x2190, 0x21FF,
                                     0x25A0, 0x25FF, 0};
    ImFont* font = io.Fonts->AddFontFromFileTTF(path.c_str(), size, nullptr, ranges);
    return font ? font : io.Fonts->AddFontDefault();
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    ImGui_ImplWin32_EnableDpiAwareness();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_CLASSDC;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.lpszClassName = L"WinXcodeWindow";
    RegisterClassExW(&window_class);

    const HWND window = CreateWindowExW(0, window_class.lpszClassName, L"WinXcode",
                                        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1440, 900,
                                        nullptr, nullptr, instance, nullptr);
    if (!window) return 1;
    // Dark title bar to match the interface.
    const BOOL dark = TRUE;
    DwmSetWindowAttribute(window, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));

    if (!create_device(window)) {
        MessageBoxW(window, L"Direct3D 11 could not be initialised.", L"WinXcode", MB_ICONERROR);
        return 1;
    }
    ShowWindow(window, show);
    UpdateWindow(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
    io.ConfigWindowsMoveFromTitleBarOnly = true;
    io.ConfigDockingWithShift = false;
    // Window layout is remembered per user.
    static std::string ini_path;
    try {
        ini_path = winx::to_utf8((winx::app_data_dir() / L"ide-layout.ini").wstring());
        io.IniFilename = ini_path.c_str();
    } catch (const std::exception&) {
        io.IniFilename = nullptr;
    }

    const float scale = ImGui_ImplWin32_GetDpiScaleForHwnd(window);
    winx::ide::Fonts fonts;
    fonts.ui = load_font(first_existing_font({L"segoeui.ttf", L"tahoma.ttf"}), 16.0f * scale);
    fonts.ui_bold =
        load_font(first_existing_font({L"seguisb.ttf", L"segoeuib.ttf", L"segoeui.ttf"}), 16.0f * scale);
    fonts.mono = load_font(
        first_existing_font({L"CascadiaMono.ttf", L"CascadiaCode.ttf", L"consola.ttf", L"cour.ttf"}),
        15.0f * scale);

    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(g_device.Get(), g_context.Get());

    int exit_code = 0;
    {
        winx::ide::IdeApp app(window, fonts, scale);
        g_app = &app;

        // `winxcode.exe <folder>` opens that project.
        int argc = 0;
        if (LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc)) {
            if (argc > 1) app.open_project(std::filesystem::absolute(argv[1]));
            LocalFree(argv);
        }

        std::string title;
        bool running = true;
        while (running) {
            MSG message;
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
                if (message.message == WM_QUIT) {
                    running = false;
                    exit_code = static_cast<int>(message.wParam);
                }
            }
            if (!running) break;

            // Nothing to draw while minimised; do not spin.
            if (IsIconic(window)) {
                Sleep(50);
                continue;
            }
            if (g_resize_width != 0 && g_resize_height != 0) {
                g_target.Reset();
                g_swap_chain->ResizeBuffers(0, g_resize_width, g_resize_height, DXGI_FORMAT_UNKNOWN, 0);
                g_resize_width = g_resize_height = 0;
                create_render_target();
            }

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();
            app.frame();
            ImGui::Render();

            const float clear[4] = {0.118f, 0.122f, 0.137f, 1.0f};
            g_context->OMSetRenderTargets(1, g_target.GetAddressOf(), nullptr);
            g_context->ClearRenderTargetView(g_target.Get(), clear);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            g_swap_chain->Present(1, 0);  // vsync

            const std::string wanted = app.window_title();
            if (wanted != title) {
                title = wanted;
                SetWindowTextW(window, winx::to_wide(title).c_str());
            }
            if (app.should_close()) DestroyWindow(window);
        }
        g_app = nullptr;
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    g_target.Reset();
    g_swap_chain.Reset();
    g_context.Reset();
    g_device.Reset();
    DestroyWindow(window);
    UnregisterClassW(window_class.lpszClassName, instance);
    CoUninitialize();
    return exit_code;
}
