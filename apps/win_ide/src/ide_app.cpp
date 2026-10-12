#include "ide_app.hpp"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <format>

#include "imgui_internal.h"
#include "imgui_stdlib.h"
#include "swift_language.hpp"
#include "winx/auth_session.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/pair_record.hpp"
#include "winx/sign_in.hpp"
#include "winx/text.hpp"

namespace winx::ide {
namespace {

namespace fs = std::filesystem;

constexpr std::uintmax_t kMaxEditableFile = 4 * 1024 * 1024;

const ImVec4 kAccent{0.26f, 0.59f, 0.98f, 1.0f};
const ImVec4 kGreen{0.35f, 0.80f, 0.45f, 1.0f};
const ImVec4 kRed{1.0f, 0.42f, 0.40f, 1.0f};
const ImVec4 kYellow{0.95f, 0.78f, 0.35f, 1.0f};
const ImVec4 kDim{0.58f, 0.60f, 0.65f, 1.0f};

const char* kNavigator = "Navigator";
const char* kEditor = "Editor";
const char* kInspector = "Inspector";
const char* kConsole = "Console";

std::string utf8(const fs::path& path) { return to_utf8(path.wstring()); }

bool is_text_like(const fs::path& path) {
    static const wchar_t* const kBinary[] = {L".png", L".jpg", L".jpeg", L".gif", L".pdf", L".zip",
                                             L".car", L".a",   L".dylib", L".o",  L".ttf", L".otf",
                                             L".mp3", L".mp4", L".mov",   L".ico", L".exe", L".dll"};
    std::wstring extension = path.extension().wstring();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
    return std::none_of(std::begin(kBinary), std::end(kBinary),
                        [&](const wchar_t* binary) { return extension == binary; });
}

// A toolbar button drawn as a shape, so no icon font is needed.
enum class Icon { Play, Stop };

bool icon_button(const char* id, Icon icon, const ImVec4& color, float size, bool enabled) {
    ImGui::BeginDisabled(!enabled);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const bool pressed = ImGui::Button(id, ImVec2(size * 1.5f, size));
    const ImVec2 center{origin.x + size * 0.75f, origin.y + size * 0.5f};
    const float r = size * 0.24f;
    const ImU32 fill = ImGui::GetColorU32(enabled ? color : ImVec4(0.45f, 0.45f, 0.48f, 1.0f));
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (icon == Icon::Play) {
        draw->AddTriangleFilled({center.x - r * 0.8f, center.y - r}, {center.x - r * 0.8f, center.y + r},
                                {center.x + r, center.y}, fill);
    } else {
        draw->AddRectFilled({center.x - r * 0.85f, center.y - r * 0.85f},
                            {center.x + r * 0.85f, center.y + r * 0.85f}, fill, 2.0f);
    }
    ImGui::EndDisabled();
    return pressed;
}

void status_dot(bool ok) {
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float height = ImGui::GetTextLineHeight();
    ImGui::GetWindowDrawList()->AddCircleFilled({origin.x + height * 0.4f, origin.y + height * 0.55f},
                                                height * 0.22f,
                                                ImGui::GetColorU32(ok ? kGreen : kYellow));
    ImGui::Dummy(ImVec2(height * 0.9f, height));
    ImGui::SameLine();
}

void labelled(const char* label, const std::string& value) {
    ImGui::TextColored(kDim, "%s", label);
    ImGui::SameLine(ImGui::GetFontSize() * 7.5f);
    ImGui::TextWrapped("%s", value.empty() ? "-" : value.c_str());
}

std::string format_expiry(std::chrono::system_clock::time_point when) {
    const auto days = std::chrono::duration_cast<std::chrono::hours>(
                          when - std::chrono::system_clock::now())
                          .count() /
                      24;
    if (days < 0) return "expired";
    if (days == 0) return "expires today";
    return std::format("expires in {} day{}", days, days == 1 ? "" : "s");
}

}  // namespace

IdeApp::IdeApp(void* window, Fonts fonts, float scale)
    : window_(window), fonts_(fonts), scale_(scale) {
    apply_style();
    refresh_account();
}

IdeApp::~IdeApp() { cancel_sign_in(); }

void IdeApp::apply_style() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImGui::StyleColorsDark(&style);
    style.WindowRounding = 0.0f;
    style.ChildRounding = 4.0f;
    style.FrameRounding = 5.0f;
    style.PopupRounding = 6.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 5.0f;
    style.ScrollbarRounding = 8.0f;
    style.WindowBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.WindowPadding = ImVec2(10, 8);
    style.FramePadding = ImVec2(8, 5);
    style.ItemSpacing = ImVec2(8, 6);
    style.IndentSpacing = 16.0f;
    style.ScrollbarSize = 12.0f;
    style.SeparatorTextBorderSize = 1.0f;

    ImVec4* c = style.Colors;
    const ImVec4 background{0.118f, 0.122f, 0.137f, 1.0f};
    const ImVec4 panel{0.153f, 0.157f, 0.176f, 1.0f};
    const ImVec4 raised{0.208f, 0.216f, 0.243f, 1.0f};
    const ImVec4 hover{0.275f, 0.286f, 0.322f, 1.0f};
    c[ImGuiCol_Text] = ImVec4(0.88f, 0.89f, 0.91f, 1.0f);
    c[ImGuiCol_TextDisabled] = kDim;
    c[ImGuiCol_WindowBg] = panel;
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg] = ImVec4(0.17f, 0.175f, 0.196f, 0.99f);
    c[ImGuiCol_Border] = ImVec4(0.08f, 0.08f, 0.09f, 1.0f);
    c[ImGuiCol_FrameBg] = raised;
    c[ImGuiCol_FrameBgHovered] = hover;
    c[ImGuiCol_FrameBgActive] = hover;
    c[ImGuiCol_TitleBg] = background;
    c[ImGuiCol_TitleBgActive] = background;
    c[ImGuiCol_MenuBarBg] = background;
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_Button] = raised;
    c[ImGuiCol_ButtonHovered] = hover;
    c[ImGuiCol_ButtonActive] = ImVec4(0.33f, 0.345f, 0.39f, 1.0f);
    c[ImGuiCol_Header] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.50f);
    c[ImGuiCol_Separator] = ImVec4(0.09f, 0.09f, 0.10f, 1.0f);
    c[ImGuiCol_Tab] = background;
    c[ImGuiCol_TabHovered] = hover;
    c[ImGuiCol_TabSelected] = panel;
    c[ImGuiCol_TabDimmed] = background;
    c[ImGuiCol_TabDimmedSelected] = panel;
    c[ImGuiCol_TabSelectedOverline] = kAccent;
    c[ImGuiCol_DockingEmptyBg] = background;
    c[ImGuiCol_CheckMark] = kAccent;
    c[ImGuiCol_SliderGrab] = kAccent;
    c[ImGuiCol_PlotHistogram] = kAccent;
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0, 0, 0, 0.55f);
    style.ScaleAllSizes(scale_);
}

std::string IdeApp::window_title() const {
    if (!workspace_.has_project()) return "WinXcode";
    return utf8(workspace_.project_dir().filename()) + " - WinXcode";
}

void IdeApp::show_message(std::string title, std::string text) {
    message_title_ = std::move(title);
    message_text_ = std::move(text);
    message_pending_ = true;
}

IdeApp::Document* IdeApp::current_document() {
    for (const auto& document : documents_) {
        if (document.get() == active_) return active_;
    }
    return nullptr;
}

bool IdeApp::any_dirty() const {
    return std::any_of(documents_.begin(), documents_.end(),
                       [](const auto& document) { return document->dirty(); });
}

void IdeApp::open_project(const fs::path& directory) {
    if (any_dirty()) save_all();
    const std::string error = workspace_.open_project(directory);
    if (!error.empty()) {
        show_message("Cannot open project", error);
        return;
    }
    documents_.clear();
    active_ = nullptr;
    // Start on the app's entry point when it is where the template puts it.
    const std::string scheme = workspace_.scheme();
    const fs::path entry = directory / L"Sources" / to_wide(scheme) / to_wide(scheme + "App.swift");
    std::error_code ec;
    if (fs::is_regular_file(entry, ec)) open_file(entry);
}

void IdeApp::choose_and_open_project() {
    const fs::path folder = pick_folder(window_, L"Open a Swift package");
    if (!folder.empty()) open_project(folder);
}

void IdeApp::open_file(const fs::path& path, int line) {
    for (const auto& document : documents_) {
        std::error_code ec;
        if (fs::equivalent(document->path, path, ec)) {
            document->select = true;
            if (line > 0) {
                document->editor.SetCursor(TextEditor::DocPos(static_cast<std::size_t>(line - 1), 0));
                document->editor.ScrollToLine(static_cast<std::size_t>(line - 1));
            }
            return;
        }
    }
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        show_message("Cannot open file", utf8(path) + " does not exist.");
        return;
    }
    if (!is_text_like(path) || fs::file_size(path, ec) > kMaxEditableFile) {
        show_message("Cannot open file",
                     utf8(path.filename()) + " is a binary or very large file and is not shown "
                                             "in the editor.");
        return;
    }
    const auto text = read_text_file(path);
    if (!text) return;

    auto document = std::make_unique<Document>();
    document->path = path;
    document->title = utf8(path.filename());
    TextEditor& editor = document->editor;
    editor.SetPalette(editor_palette());
    editor.SetTabSize(4);
    editor.SetInsertSpacesOnTabs(true);
    editor.SetShowLineNumbersEnabled(true);
    editor.SetShowMatchingBrackets(true);
    editor.SetShowCurrentLineHighlightEnabled(true);
    editor.SetShowWhitespacesEnabled(false);
    std::wstring extension = path.extension().wstring();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);
    if (extension == L".swift") {
        editor.SetLanguage(swift_language());
    } else if (extension == L".c" || extension == L".h" || extension == L".m") {
        editor.SetLanguage(TextEditor::Language::C());
    } else if (extension == L".cpp" || extension == L".hpp" || extension == L".mm") {
        editor.SetLanguage(TextEditor::Language::Cpp());
    }
    editor.SetText(*text);
    document->saved_undo_index = editor.GetUndoIndex();
    if (line > 0) {
        editor.SetCursor(TextEditor::DocPos(static_cast<std::size_t>(line - 1), 0));
        editor.ScrollToLine(static_cast<std::size_t>(line - 1));
    }
    document->select = true;
    documents_.push_back(std::move(document));
}

bool IdeApp::save(Document& document) {
    try {
        write_text_file(document.path, document.editor.GetText());
        document.saved_undo_index = document.editor.GetUndoIndex();
        return true;
    } catch (const std::exception& error) {
        show_message("Cannot save", error.what());
        return false;
    }
}

void IdeApp::save_all() {
    for (const auto& document : documents_) {
        if (document->dirty()) save(*document);
    }
}

void IdeApp::request_close() {
    if (any_dirty()) {
        close_requested_ = true;
    } else {
        close_confirmed_ = true;
    }
}

void IdeApp::refresh_account() {
    account_summary_.clear();
    identity_summary_.clear();
    signed_in_ = false;
    try {
        const auth::AuthState state = auth::AuthStore(app_data_dir()).load();
        if (state.mode == auth::AuthState::Mode::ApiKey) {
            signed_in_ = true;
            account_summary_ = "API key " + state.key_id;
        } else if (state.mode == auth::AuthState::Mode::AppleId) {
            signed_in_ = true;
            account_summary_ = state.apple_id + "\n" + state.team_name + " (" + state.team_id + ")";
        }
        if (signed_in_) {
            if (const auto stored = auth::IdentityStore(app_data_dir()).load(state.account())) {
                identity_summary_ = stored->identity.info().common_name + "\n" +
                                    format_expiry(stored->identity.info().not_after);
            }
        }
    } catch (const std::exception&) {
        // Unreadable state is shown as "not signed in".
    }
    workspace_.refresh_prerequisites();
}

void IdeApp::handle_shortcuts() {
    const ImGuiInputFlags global = ImGuiInputFlags_RouteGlobal;
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_S, global)) {
        if (Document* document = current_document()) save(*document);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_S, global)) save_all();
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O, global)) choose_and_open_project();
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_R, global)) {
        save_all();
        workspace_.start(RunMode::Run);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_B, global)) {
        save_all();
        workspace_.start(RunMode::Build);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_Period, global)) workspace_.stop();
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_W, global)) {
        if (Document* document = current_document()) document->keep_open = false;
    }
}

void IdeApp::draw_menu_bar() {
    if (!ImGui::BeginMainMenuBar()) return;
    Document* document = current_document();
    const bool has_project = workspace_.has_project();

    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("New Project...")) {
            new_project_open_ = true;
            if (new_project_location_.empty()) {
                wchar_t profile[MAX_PATH];
                if (GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH) > 0) {
                    new_project_location_ = to_utf8(profile);
                }
            }
        }
        if (ImGui::MenuItem("Open Project...", "Ctrl+O")) choose_and_open_project();
        ImGui::Separator();
        if (ImGui::MenuItem("Save", "Ctrl+S", false, document != nullptr)) save(*document);
        if (ImGui::MenuItem("Save All", "Ctrl+Shift+S", false, !documents_.empty())) save_all();
        if (ImGui::MenuItem("Close Tab", "Ctrl+W", false, document != nullptr)) {
            document->keep_open = false;
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit")) request_close();
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Edit", document != nullptr)) {
        TextEditor& editor = document->editor;
        if (ImGui::MenuItem("Undo", "Ctrl+Z", false, editor.CanUndo())) editor.Undo();
        if (ImGui::MenuItem("Redo", "Ctrl+Y", false, editor.CanRedo())) editor.Redo();
        ImGui::Separator();
        if (ImGui::MenuItem("Cut", "Ctrl+X")) editor.Cut();
        if (ImGui::MenuItem("Copy", "Ctrl+C")) editor.Copy();
        if (ImGui::MenuItem("Paste", "Ctrl+V")) editor.Paste();
        if (ImGui::MenuItem("Select All", "Ctrl+A")) editor.SelectAll();
        ImGui::Separator();
        if (ImGui::MenuItem("Find and Replace...", "Ctrl+F")) editor.OpenFindReplaceWindow();
        if (ImGui::MenuItem("Toggle Comment", "Ctrl+/")) editor.ToggleComments();
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Product")) {
        const bool idle = has_project && !workspace_.running();
        if (ImGui::MenuItem("Run", "Ctrl+R", false, idle)) {
            save_all();
            workspace_.start(RunMode::Run);
        }
        if (ImGui::MenuItem("Build", "Ctrl+B", false, idle)) {
            save_all();
            workspace_.start(RunMode::Build);
        }
        if (ImGui::MenuItem("Stop", "Ctrl+.", false, workspace_.running())) workspace_.stop();
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Account")) {
        if (ImGui::MenuItem(signed_in_ ? "Switch Account..." : "Sign In...")) sign_in_.open = true;
        if (ImGui::MenuItem("Sign Out", nullptr, false, signed_in_)) {
            engine::sign_out();
            refresh_account();
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About WinXcode")) about_open_ = true;
        ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
}

void IdeApp::draw_toolbar(const ImGuiViewport* viewport, float height) {
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.118f, 0.122f, 0.137f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10 * scale_, 7 * scale_));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
                                   ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav;
    if (ImGui::Begin("##toolbar", nullptr, flags)) {
        const float button = height - 14 * scale_;
        const bool has_project = workspace_.has_project();
        const bool running = workspace_.running();

        if (icon_button("##run", Icon::Play, kGreen, button, has_project && !running)) {
            save_all();
            workspace_.start(RunMode::Run);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("Build, sign and install on the selected device (Ctrl+R)");
        }
        ImGui::SameLine();
        if (icon_button("##stop", Icon::Stop, kRed, button, running)) workspace_.stop();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("Stop the current build (Ctrl+.)");
        }

        // Scheme and destination, as in Xcode's toolbar.
        ImGui::SameLine(0, 18 * scale_);
        ImGui::AlignTextToFramePadding();
        ImGui::PushFont(fonts_.ui_bold);
        ImGui::TextUnformatted(has_project ? workspace_.scheme().c_str() : "No Project");
        ImGui::PopFont();
        ImGui::SameLine();
        ImGui::TextColored(kDim, ">");
        ImGui::SameLine();

        const auto& devices = workspace_.devices();
        const int selected = workspace_.selected_device();
        const std::string preview =
            selected >= 0 ? devices[static_cast<std::size_t>(selected)].label()
                          : workspace_.device_status().empty() ? "No Device"
                                                               : workspace_.device_status();
        ImGui::SetNextItemWidth(280 * scale_);
        if (ImGui::BeginCombo("##device", preview.c_str())) {
            if (devices.empty()) {
                ImGui::TextDisabled("Connect an iPhone with a USB cable and unlock it.");
            }
            for (int i = 0; i < static_cast<int>(devices.size()); ++i) {
                const DeviceEntry& entry = devices[static_cast<std::size_t>(i)];
                ImGui::PushID(i);
                if (ImGui::Selectable(entry.label().c_str(), i == selected)) {
                    workspace_.select_device(i);
                }
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", entry.udid.c_str());
                ImGui::PopID();
            }
            ImGui::EndCombo();
        }

        // Activity area.
        ImGui::SameLine(0, 18 * scale_);
        const float remaining = ImGui::GetContentRegionAvail().x;
        if (running) {
            const int percent = workspace_.progress();
            const std::string label =
                percent >= 0 ? std::format("{} {}%", workspace_.stage(), percent) : workspace_.stage();
            // An indeterminate bar sweeps back and forth.
            const float fraction = percent >= 0 ? static_cast<float>(percent) / 100.0f
                                                : -static_cast<float>(ImGui::GetTime());
            ImGui::ProgressBar(fraction, ImVec2(std::min(remaining, 360 * scale_), 0),
                               label.c_str());
        } else if (!workspace_.last_result().empty()) {
            ImGui::AlignTextToFramePadding();
            ImGui::TextColored(workspace_.last_succeeded() ? kGreen : kRed, "%s",
                               workspace_.last_result().c_str());
        } else {
            ImGui::AlignTextToFramePadding();
            ImGui::TextColored(kDim, "%s", has_project ? "Ready" : "Open a project to begin");
        }
    }
    ImGui::End();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
}

void IdeApp::draw_dock_space(const ImGuiViewport* viewport, float top) {
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + top));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - top));
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
                                   ImGuiWindowFlags_NoBringToFrontOnFocus |
                                   ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoBackground;
    ImGui::Begin("##dock_host", nullptr, flags);
    ImGui::PopStyleVar();

    const ImGuiID dock = ImGui::GetID("WinXcodeDock");
    if (!layout_built_) {
        layout_built_ = true;
        // Keep a layout the user rearranged in an earlier session.
        if (ImGui::DockBuilderGetNode(dock) == nullptr) {
            ImGui::DockBuilderRemoveNode(dock);
            ImGui::DockBuilderAddNode(dock, ImGuiDockNodeFlags_DockSpace);
            ImGui::DockBuilderSetNodeSize(dock, ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - top));
            ImGuiID center = dock;
            const ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.19f, nullptr, &center);
            const ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.26f, nullptr, &center);
            const ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.30f, nullptr, &center);
            ImGui::DockBuilderDockWindow(kNavigator, left);
            ImGui::DockBuilderDockWindow(kInspector, right);
            ImGui::DockBuilderDockWindow(kConsole, bottom);
            ImGui::DockBuilderDockWindow(kEditor, center);
            ImGui::DockBuilderFinish(dock);
        }
    }
    ImGui::DockSpace(dock, ImVec2(0, 0), ImGuiDockNodeFlags_None);
    ImGui::End();
}

void IdeApp::draw_tree(const FileNode& node, int depth) {
    const bool root = depth == 0;
    if (!node.directory) {
        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen |
                                   ImGuiTreeNodeFlags_SpanAvailWidth;
        const Document* document = current_document();
        if (document && document->path == node.path) flags |= ImGuiTreeNodeFlags_Selected;
        ImGui::TreeNodeEx(node.name.c_str(), flags);
        if (ImGui::IsItemClicked()) open_file(node.path);
        return;
    }
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_OpenOnArrow |
                               ImGuiTreeNodeFlags_OpenOnDoubleClick;
    // The package, Sources and each target folder start expanded.
    if (depth <= 2) flags |= ImGuiTreeNodeFlags_DefaultOpen;
    ImGui::PushStyleColor(ImGuiCol_Text, root ? ImGui::GetStyleColorVec4(ImGuiCol_Text)
                                              : ImVec4(0.72f, 0.80f, 0.93f, 1.0f));
    const bool open = ImGui::TreeNodeEx(node.name.c_str(), flags);
    ImGui::PopStyleColor();
    if (open) {
        for (const FileNode& child : node.children) draw_tree(child, depth + 1);
        ImGui::TreePop();
    }
}

void IdeApp::draw_navigator() {
    if (ImGui::Begin(kNavigator)) {
        if (!workspace_.has_project()) {
            ImGui::TextWrapped("No project is open.");
            ImGui::Spacing();
            if (ImGui::Button("Open Project...")) choose_and_open_project();
            if (ImGui::Button("New Project...")) new_project_open_ = true;
        } else {
            draw_tree(workspace_.tree(), 0);
        }
    }
    ImGui::End();
}

void IdeApp::draw_welcome() {
    const ImVec2 available = ImGui::GetContentRegionAvail();
    ImGui::SetCursorPos(ImVec2(available.x * 0.5f - 230 * scale_, available.y * 0.18f));
    ImGui::BeginGroup();
    ImGui::PushFont(fonts_.ui_bold);
    ImGui::TextUnformatted("WinXcode");
    ImGui::PopFont();
    ImGui::TextColored(kDim, "Build, sign and install iOS apps from Windows.");
    ImGui::Dummy(ImVec2(0, 10 * scale_));
    if (!workspace_.has_project()) {
        if (ImGui::Button("Open Project...", ImVec2(150 * scale_, 0))) choose_and_open_project();
        ImGui::SameLine();
        if (ImGui::Button("New Project...", ImVec2(150 * scale_, 0))) new_project_open_ = true;
    } else {
        ImGui::TextColored(kDim, "Choose a file in the navigator to edit it.");
    }
    ImGui::Dummy(ImVec2(0, 14 * scale_));
    ImGui::SeparatorText("What this PC still needs");
    if (workspace_.prerequisites().empty()) ImGui::TextColored(kDim, "Checking...");
    for (const engine::Prerequisite& item : workspace_.prerequisites()) {
        status_dot(item.ready);
        ImGui::TextUnformatted(item.name.c_str());
        ImGui::SameLine(200 * scale_);
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + 420 * scale_);
        ImGui::TextColored(kDim, "%s", item.detail.c_str());
        ImGui::PopTextWrapPos();
    }
    ImGui::EndGroup();
}

void IdeApp::draw_editor() {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    const bool visible = ImGui::Begin(kEditor, nullptr, ImGuiWindowFlags_NoScrollbar |
                                                            ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();
    if (visible) {
        if (documents_.empty()) {
            active_ = nullptr;
            draw_welcome();
        } else if (ImGui::BeginTabBar("##documents", ImGuiTabBarFlags_Reorderable |
                                                          ImGuiTabBarFlags_AutoSelectNewTabs |
                                                          ImGuiTabBarFlags_FittingPolicyScroll)) {
            for (const auto& document : documents_) {
                ImGuiTabItemFlags flags = ImGuiTabItemFlags_None;
                if (document->dirty()) flags |= ImGuiTabItemFlags_UnsavedDocument;
                if (document->select) {
                    flags |= ImGuiTabItemFlags_SetSelected;
                    document->select = false;
                }
                ImGui::PushID(document.get());
                if (ImGui::BeginTabItem(document->title.c_str(), &document->keep_open, flags)) {
                    active_ = document.get();
                    ImGui::PushFont(fonts_.mono);
                    document->editor.Render("##text", ImGui::GetContentRegionAvail());
                    ImGui::PopFont();
                    ImGui::EndTabItem();
                }
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", utf8(document->path).c_str());
                ImGui::PopID();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();

    // Closing a modified tab saves it: there is no undo for a discarded edit.
    for (const auto& document : documents_) {
        if (!document->keep_open && document->dirty()) {
            if (!save(*document)) document->keep_open = true;
        }
    }
    std::erase_if(documents_, [&](const auto& document) {
        if (document->keep_open) return false;
        if (document.get() == active_) active_ = nullptr;
        return true;
    });
}

void IdeApp::draw_inspector() {
    if (ImGui::Begin(kInspector)) {
        ImGui::SeparatorText("Target");
        if (!workspace_.has_project()) {
            ImGui::TextColored(kDim, "No project");
        } else {
            build::ProjectConfig& config = workspace_.config();
            labelled("Product", workspace_.scheme());
            labelled("Bundle ID", config.bundle_id_for(workspace_.scheme()));
            labelled("iOS target", workspace_.deployment_target().empty()
                                       ? "from Package.swift"
                                       : workspace_.deployment_target());

            ImGui::Spacing();
            ImGui::TextColored(kDim, "xtool.yml");
            const float width = -1.0f;
            bool edited = false;
            const auto field = [&](const char* label, const char* hint, std::string& value) {
                ImGui::SetNextItemWidth(width);
                ImGui::InputTextWithHint(label, hint, &value);
                edited = edited || ImGui::IsItemDeactivatedAfterEdit();
            };
            field("##bundle", "bundleID (e.g. com.example.Hello)", config.bundle_id);
            field("##org", "orgID, used when bundleID is empty", config.org_id);
            field("##icon", "iconPath (a .png)", config.icon_path);
            field("##info", "infoPath (extra Info.plist keys)", config.info_path);
            field("##entitlements", "entitlementsPath", config.entitlements_path);
            if (edited) {
                if (config.bundle_id.empty() && config.org_id.empty()) config.org_id = "com.example";
                const std::string error = workspace_.save_config();
                if (!error.empty()) show_message("Cannot save xtool.yml", error);
            }
        }

        ImGui::SeparatorText("Signing");
        if (signed_in_) {
            labelled("Account", account_summary_);
            labelled("Certificate", identity_summary_.empty()
                                        ? "requested on first run"
                                        : identity_summary_);
            if (ImGui::Button("Switch Account...")) sign_in_.open = true;
        } else {
            ImGui::TextWrapped("Sign in to request a certificate and provisioning profile.");
            if (ImGui::Button("Sign In...")) sign_in_.open = true;
        }

        ImGui::SeparatorText("Device");
        const int selected = workspace_.selected_device();
        if (selected < 0) {
            ImGui::TextColored(kDim, "%s", workspace_.device_status().empty()
                                               ? "No device attached"
                                               : workspace_.device_status().c_str());
        } else {
            const DeviceEntry& entry = workspace_.devices()[static_cast<std::size_t>(selected)];
            labelled("Name", entry.name);
            labelled("iOS", entry.os_version);
            labelled("UDID", entry.udid);
            labelled("Connection", entry.usb ? "USB" : "Wi-Fi");
            bool paired = false;
            try {
                paired = device::load_pair_record(entry.udid).has_value();
            } catch (const std::exception&) {
            }
            labelled("Trusts this PC", paired ? "yes" : "no - unlock it and tap Trust");
        }

        ImGui::SeparatorText("Environment");
        for (const engine::Prerequisite& item : workspace_.prerequisites()) {
            status_dot(item.ready);
            ImGui::TextUnformatted(item.name.c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", item.detail.c_str());
        }
        if (ImGui::SmallButton("Check again")) refresh_account();
    }
    ImGui::End();
}

void IdeApp::draw_console() {
    if (ImGui::Begin(kConsole)) {
        const auto& diagnostics = workspace_.diagnostics();
        const auto errors = std::count_if(diagnostics.begin(), diagnostics.end(), [](const auto& d) {
            return d.severity == build::Diagnostic::Severity::Error;
        });
        if (ImGui::BeginTabBar("##console_tabs")) {
            if (ImGui::BeginTabItem("Build")) {
                if (ImGui::SmallButton("Clear")) workspace_.clear_build_log();
                ImGui::Separator();
                ImGui::BeginChild("##build_log", ImVec2(0, 0), ImGuiChildFlags_None,
                                  ImGuiWindowFlags_HorizontalScrollbar);
                ImGui::PushFont(fonts_.mono);
                const auto& lines = workspace_.build_log();
                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(lines.size()));
                while (clipper.Step()) {
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                        const ConsoleLine& line = lines[static_cast<std::size_t>(i)];
                        switch (line.kind) {
                            case ConsoleLine::Kind::Stage:
                                ImGui::TextColored(kAccent, "==> %s", line.text.c_str());
                                break;
                            case ConsoleLine::Kind::Error:
                                ImGui::TextColored(kRed, "%s", line.text.c_str());
                                break;
                            case ConsoleLine::Kind::Warning:
                                ImGui::TextColored(kYellow, "%s", line.text.c_str());
                                break;
                            case ConsoleLine::Kind::Success:
                                ImGui::TextColored(kGreen, "%s", line.text.c_str());
                                break;
                            case ConsoleLine::Kind::Plain:
                                ImGui::TextUnformatted(line.text.c_str());
                                break;
                        }
                    }
                }
                ImGui::PopFont();
                if (seen_build_revision_ != workspace_.build_log_revision()) {
                    seen_build_revision_ = workspace_.build_log_revision();
                    ImGui::SetScrollHereY(1.0f);
                }
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            const std::string issues_label =
                std::format("Issues ({})###issues", diagnostics.size());
            ImGuiTabItemFlags issue_flags = ImGuiTabItemFlags_None;
            if (focus_issues_) {
                issue_flags |= ImGuiTabItemFlags_SetSelected;
                focus_issues_ = false;
            }
            if (ImGui::BeginTabItem(issues_label.c_str(), nullptr, issue_flags)) {
                if (diagnostics.empty()) {
                    ImGui::TextColored(kDim, "No issues from the last build.");
                } else {
                    ImGui::TextColored(kDim, "%d error(s). Click an issue to open it.",
                                       static_cast<int>(errors));
                }
                ImGui::BeginChild("##issues");
                for (std::size_t i = 0; i < diagnostics.size(); ++i) {
                    const build::Diagnostic& diagnostic = diagnostics[i];
                    const ImVec4 color =
                        diagnostic.severity == build::Diagnostic::Severity::Error     ? kRed
                        : diagnostic.severity == build::Diagnostic::Severity::Warning ? kYellow
                                                                                      : kDim;
                    ImGui::PushID(static_cast<int>(i));
                    const std::string file = utf8(fs::path(to_wide(diagnostic.file)).filename());
                    const std::string label = std::format("{}:{}  {}", file, diagnostic.line,
                                                          diagnostic.message);
                    ImGui::PushStyleColor(ImGuiCol_Text, color);
                    if (ImGui::Selectable(label.c_str())) {
                        open_file(to_wide(diagnostic.file), diagnostic.line);
                    }
                    ImGui::PopStyleColor();
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("%s:%d:%d", diagnostic.file.c_str(), diagnostic.line,
                                          diagnostic.column);
                    }
                    ImGui::PopID();
                }
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Device Log")) {
                if (ImGui::Checkbox("Stream", &stream_device_log_)) {
                    workspace_.set_device_log_enabled(stream_device_log_);
                }
                ImGui::SameLine();
                ImGui::SetNextItemWidth(260 * scale_);
                ImGui::InputTextWithHint("##filter", "Filter (e.g. the app name)",
                                         &device_log_filter_);
                ImGui::SameLine();
                if (ImGui::SmallButton("Clear")) workspace_.clear_device_log();
                ImGui::Separator();
                ImGui::BeginChild("##device_log", ImVec2(0, 0), ImGuiChildFlags_None,
                                  ImGuiWindowFlags_HorizontalScrollbar);
                ImGui::PushFont(fonts_.mono);
                if (!stream_device_log_ && workspace_.device_log().empty()) {
                    ImGui::TextColored(kDim, "Tick Stream to follow the selected device's log.");
                }
                for (const std::string& line : workspace_.device_log()) {
                    if (!device_log_filter_.empty() &&
                        line.find(device_log_filter_) == std::string::npos) {
                        continue;
                    }
                    ImGui::TextUnformatted(line.c_str());
                }
                ImGui::PopFont();
                if (seen_device_revision_ != workspace_.device_log_revision()) {
                    seen_device_revision_ = workspace_.device_log_revision();
                    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 40) ImGui::SetScrollHereY(1.0f);
                }
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void IdeApp::cancel_sign_in() {
    {
        const std::lock_guard lock(sign_in_.mutex);
        sign_in_.code_reply = std::string{};
        sign_in_.team_reply = static_cast<std::size_t>(-1);
    }
    sign_in_.wake.notify_all();
    sign_in_.worker = std::jthread();  // joins
}

void IdeApp::start_sign_in() {
    SignIn& s = sign_in_;
    if (s.worker.joinable()) s.worker.join();
    {
        const std::lock_guard lock(s.mutex);
        s.busy = true;
        s.finished = false;
        s.error.clear();
        s.status = "Contacting Apple...";
        s.needs_code = false;
        s.needs_team = false;
        s.code_reply.reset();
        s.team_reply.reset();
    }
    const int mode = s.mode;
    engine::ApiKeyLogin key_login{s.key_id, s.issuer_id, {}};
    const std::string key_path = s.key_path;
    const std::string apple_id = s.apple_id;
    std::string password = std::move(s.password);
    s.password.clear();

    s.worker = std::jthread([this, mode, key_login, key_path, apple_id,
                             password = std::move(password)]() mutable {
        SignIn& state = sign_in_;
        std::string error;
        try {
            if (mode == 0) {
                const auto pem = read_text_file(to_wide(key_path));
                if (!pem) throw auth::KeyError("cannot read the .p8 key file");
                key_login.p8_pem = *pem;
                engine::sign_in_with_api_key(key_login);
            } else {
                engine::AppleIdPrompts prompts;
                prompts.status = [&](const std::string& message) {
                    const std::lock_guard lock(state.mutex);
                    state.status = message;
                };
                prompts.verification_code = [&](bool sms) {
                    std::unique_lock lock(state.mutex);
                    state.needs_code = true;
                    state.code_is_sms = sms;
                    state.code_reply.reset();
                    state.wake.wait(lock, [&] { return state.code_reply.has_value(); });
                    state.needs_code = false;
                    return *state.code_reply;
                };
                prompts.choose_team = [&](const std::vector<auth::Team>& teams) {
                    std::unique_lock lock(state.mutex);
                    state.teams = teams;
                    state.needs_team = true;
                    state.team_reply.reset();
                    state.wake.wait(lock, [&] { return state.team_reply.has_value(); });
                    state.needs_team = false;
                    return *state.team_reply;
                };
                engine::sign_in_with_apple_id(apple_id, std::move(password), "", "", prompts);
            }
        } catch (const std::exception& failure) {
            error = failure.what();
        }
        const std::lock_guard lock(state.mutex);
        state.error = std::move(error);
        state.busy = false;
        state.finished = true;
    });
}

void IdeApp::draw_sign_in() {
    SignIn& s = sign_in_;
    if (s.open && !ImGui::IsPopupOpen("Sign In")) ImGui::OpenPopup("Sign In");
    ImGui::SetNextWindowSize(ImVec2(620 * scale_, 0), ImGuiCond_Appearing);
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("Sign In", nullptr, ImGuiWindowFlags_NoSavedSettings)) return;

    // Snapshot the worker's state for this frame.
    bool busy = false;
    bool finished = false;
    bool needs_code = false;
    bool needs_team = false;
    bool code_is_sms = false;
    std::string status;
    std::string error;
    std::vector<auth::Team> teams;
    {
        const std::lock_guard lock(s.mutex);
        busy = s.busy;
        finished = s.finished;
        needs_code = s.needs_code;
        needs_team = s.needs_team;
        code_is_sms = s.code_is_sms;
        status = s.status;
        error = s.error;
        if (needs_team) teams = s.teams;
    }
    if (finished && error.empty()) {
        {
            const std::lock_guard lock(s.mutex);
            s.finished = false;
        }
        s.open = false;
        s.accepted_warning = false;
        refresh_account();
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }

    ImGui::BeginDisabled(busy);
    ImGui::RadioButton("App Store Connect API key (Apple's documented API)", &s.mode, 0);
    ImGui::RadioButton("Apple ID and password (unofficial, as Xcode signs in)", &s.mode, 1);
    ImGui::EndDisabled();
    ImGui::Spacing();

    const std::string_view warning = s.mode == 0 ? auth::api_key_warning() : auth::apple_id_warning();
    ImGui::BeginChild("##warning", ImVec2(0, 190 * scale_), ImGuiChildFlags_Borders);
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextUnformatted(warning.data(), warning.data() + warning.size());
    ImGui::PopTextWrapPos();
    ImGui::EndChild();
    ImGui::BeginDisabled(busy);
    ImGui::Checkbox("I have read this and want to continue", &s.accepted_warning);
    ImGui::Spacing();

    const float field_width = 380 * scale_;
    if (s.mode == 0) {
        ImGui::SetNextItemWidth(field_width);
        ImGui::InputTextWithHint("Key ID", "e.g. 2X9R4HXF34", &s.key_id);
        ImGui::SetNextItemWidth(field_width);
        ImGui::InputTextWithHint("Issuer ID", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", &s.issuer_id);
        ImGui::SetNextItemWidth(field_width);
        ImGui::InputTextWithHint("Key file", "AuthKey_XXXXXXXXXX.p8", &s.key_path);
        ImGui::SameLine();
        if (ImGui::Button("Browse...")) {
            const fs::path file = pick_file(window_, L"Choose the API key file",
                                            L"App Store Connect key (*.p8)", L"*.p8");
            if (!file.empty()) s.key_path = utf8(file);
        }
    } else {
        ImGui::SetNextItemWidth(field_width);
        ImGui::InputTextWithHint("Apple ID", "name@example.com", &s.apple_id);
        ImGui::SetNextItemWidth(field_width);
        ImGui::InputText("Password", &s.password, ImGuiInputTextFlags_Password);
    }
    ImGui::EndDisabled();

    if (needs_code) {
        ImGui::Separator();
        ImGui::TextWrapped("%s", code_is_sms
                                     ? "Enter the code Apple sent by text message."
                                     : "Enter the six-digit code shown on your Apple device.");
        ImGui::SetNextItemWidth(160 * scale_);
        const bool entered = ImGui::InputText("##code", &s.code,
                                              ImGuiInputTextFlags_CharsDecimal |
                                                  ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        const auto reply = [&](std::string value) {
            {
                const std::lock_guard lock(s.mutex);
                s.code_reply = std::move(value);
            }
            s.code.clear();
            s.wake.notify_all();
        };
        if (ImGui::Button("Verify") || entered) reply(s.code);
        if (!code_is_sms) {
            ImGui::SameLine();
            if (ImGui::Button("Text me instead")) reply("sms");
        }
    }
    if (needs_team) {
        ImGui::Separator();
        ImGui::TextUnformatted("Choose a team:");
        for (std::size_t i = 0; i < teams.size(); ++i) {
            const std::string label = std::format("{} ({}){}", teams[i].name, teams[i].id,
                                                  teams[i].free ? " - free" : "");
            if (ImGui::Selectable(label.c_str())) {
                {
                    const std::lock_guard lock(s.mutex);
                    s.team_reply = i;
                }
                s.wake.notify_all();
            }
        }
    }

    ImGui::Separator();
    if (busy) ImGui::TextColored(kDim, "%s", status.c_str());
    if (!error.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(kRed, "%s", error.c_str());
        ImGui::PopTextWrapPos();
    }

    const bool complete = s.mode == 0 ? !s.key_id.empty() && !s.issuer_id.empty() && !s.key_path.empty()
                                      : !s.apple_id.empty() && !s.password.empty();
    ImGui::BeginDisabled(busy || !s.accepted_warning || !complete);
    if (ImGui::Button("Sign In", ImVec2(120 * scale_, 0))) start_sign_in();
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120 * scale_, 0))) {
        cancel_sign_in();
        SecureZeroMemory(s.password.data(), s.password.size());
        s.password.clear();
        {
            const std::lock_guard lock(s.mutex);
            s.busy = false;
            s.finished = false;
            s.error.clear();
        }
        s.open = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void IdeApp::draw_new_project() {
    if (new_project_open_ && !ImGui::IsPopupOpen("New Project")) ImGui::OpenPopup("New Project");
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(560 * scale_, 0), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("New Project", nullptr, ImGuiWindowFlags_NoSavedSettings)) return;

    ImGui::TextWrapped("Creates a SwiftUI app as a Swift package with an xtool.yml, the same "
                       "layout xtool uses.");
    ImGui::Spacing();
    const float width = 360 * scale_;
    ImGui::SetNextItemWidth(width);
    ImGui::InputText("Name", &new_project_name_);
    ImGui::SetNextItemWidth(width);
    ImGui::InputText("Organization ID", &new_project_org_);
    ImGui::SetNextItemWidth(width);
    ImGui::InputText("Location", &new_project_location_);
    ImGui::SameLine();
    if (ImGui::Button("Browse...")) {
        const fs::path folder = pick_folder(window_, L"Choose where to create the project");
        if (!folder.empty()) new_project_location_ = utf8(folder);
    }
    const bool valid = build::is_valid_project_name(new_project_name_) &&
                       !new_project_org_.empty() && !new_project_location_.empty();
    if (!new_project_name_.empty() && !build::is_valid_project_name(new_project_name_)) {
        ImGui::TextColored(kYellow, "Use letters, digits and underscores, starting with a letter.");
    } else {
        ImGui::TextColored(kDim, "Bundle ID: %s.%s", new_project_org_.c_str(),
                           new_project_name_.c_str());
    }
    ImGui::Separator();
    ImGui::BeginDisabled(!valid);
    if (ImGui::Button("Create", ImVec2(120 * scale_, 0))) {
        const fs::path directory = fs::path(to_wide(new_project_location_)) / to_wide(new_project_name_);
        try {
            build::create_project(directory, new_project_name_, new_project_org_);
            new_project_open_ = false;
            ImGui::CloseCurrentPopup();
            open_project(directory);
        } catch (const std::exception& error) {
            show_message("Cannot create project", error.what());
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120 * scale_, 0))) {
        new_project_open_ = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void IdeApp::draw_dialogs() {
    draw_sign_in();
    draw_new_project();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();

    if (about_open_ && !ImGui::IsPopupOpen("About WinXcode")) ImGui::OpenPopup("About WinXcode");
    ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::BeginPopupModal("About WinXcode", nullptr, ImGuiWindowFlags_AlwaysAutoResize |
                                                              ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::TextUnformatted("WinXcode 0.1");
        ImGui::TextColored(kDim, "A native Windows toolchain for iOS apps, modelled on xtool.");
        ImGui::Spacing();
        ImGui::TextUnformatted("Not affiliated with or endorsed by Apple Inc.");
        ImGui::Spacing();
        if (ImGui::Button("Close", ImVec2(100 * scale_, 0))) {
            about_open_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if (close_requested_ && !ImGui::IsPopupOpen("Unsaved Changes")) ImGui::OpenPopup("Unsaved Changes");
    ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::BeginPopupModal("Unsaved Changes", nullptr, ImGuiWindowFlags_AlwaysAutoResize |
                                                               ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::TextUnformatted("Some files have changes that are not saved.");
        ImGui::Spacing();
        if (ImGui::Button("Save All and Exit")) {
            save_all();
            close_confirmed_ = !any_dirty();
            close_requested_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Exit Without Saving")) {
            close_confirmed_ = true;
            close_requested_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            close_requested_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if (message_pending_) {
        ImGui::OpenPopup("##message");
        message_pending_ = false;
    }
    ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(480 * scale_, 0), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("##message", nullptr, ImGuiWindowFlags_NoTitleBar |
                                                         ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::PushFont(fonts_.ui_bold);
        ImGui::TextUnformatted(message_title_.c_str());
        ImGui::PopFont();
        ImGui::Spacing();
        ImGui::TextWrapped("%s", message_text_.c_str());
        ImGui::Spacing();
        if (ImGui::Button("OK", ImVec2(100 * scale_, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void IdeApp::frame() {
    const std::size_t issues_before = workspace_.diagnostics().size();
    const bool was_running = workspace_.running();
    workspace_.poll();
    // When a build finishes with problems, bring them into view.
    if (was_running && !workspace_.running()) {
        refresh_account();
        if (!workspace_.last_succeeded() && !workspace_.diagnostics().empty()) focus_issues_ = true;
    }
    (void)issues_before;

    handle_shortcuts();
    draw_menu_bar();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const float toolbar_height = ImGui::GetFrameHeight() + 16 * scale_;
    draw_toolbar(viewport, toolbar_height);
    draw_dock_space(viewport, toolbar_height);
    draw_navigator();
    draw_editor();
    draw_inspector();
    draw_console();
    draw_dialogs();
}

}  // namespace winx::ide
