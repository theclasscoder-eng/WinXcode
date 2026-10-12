#include <windows.h>

#include <shobjidl.h>
#include <wrl/client.h>

#include "ide_app.hpp"

namespace winx::ide {
namespace {

using Microsoft::WRL::ComPtr;

std::filesystem::path run_dialog(void* owner, const wchar_t* title, bool folders,
                                 const wchar_t* filter_name, const wchar_t* filter_pattern) {
    ComPtr<IFileOpenDialog> dialog;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&dialog)))) {
        return {};
    }
    DWORD options = 0;
    dialog->GetOptions(&options);
    options |= FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
    if (folders) options |= FOS_PICKFOLDERS;
    dialog->SetOptions(options);
    dialog->SetTitle(title);
    if (!folders && filter_name && filter_pattern) {
        const COMDLG_FILTERSPEC filters[] = {{filter_name, filter_pattern}, {L"All files", L"*.*"}};
        dialog->SetFileTypes(2, filters);
    }
    if (FAILED(dialog->Show(static_cast<HWND>(owner)))) return {};  // includes "cancelled"

    ComPtr<IShellItem> item;
    if (FAILED(dialog->GetResult(&item))) return {};
    PWSTR raw = nullptr;
    if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &raw)) || !raw) return {};
    std::filesystem::path result(raw);
    CoTaskMemFree(raw);
    return result;
}

}  // namespace

std::filesystem::path pick_folder(void* owner_window, const wchar_t* title) {
    return run_dialog(owner_window, title, true, nullptr, nullptr);
}

std::filesystem::path pick_file(void* owner_window, const wchar_t* title, const wchar_t* filter_name,
                                const wchar_t* filter_pattern) {
    return run_dialog(owner_window, title, false, filter_name, filter_pattern);
}

}  // namespace winx::ide
