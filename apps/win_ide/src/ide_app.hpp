#pragma once

#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "TextEditor.h"
#include "imgui.h"
#include "winx/apple_id.hpp"
#include "workspace.hpp"

namespace winx::ide {

// Native pickers; implemented in platform.cpp. Empty result means cancelled.
std::filesystem::path pick_folder(void* owner_window, const wchar_t* title);
std::filesystem::path pick_file(void* owner_window, const wchar_t* title, const wchar_t* filter_name,
                                const wchar_t* filter_pattern);

struct Fonts {
    ImFont* ui = nullptr;
    ImFont* ui_bold = nullptr;
    ImFont* mono = nullptr;
};

// The whole user interface. One instance lives for the life of the window;
// frame() is called once per rendered frame.
class IdeApp {
public:
    IdeApp(void* window, Fonts fonts, float scale);
    ~IdeApp();

    void frame();
    // The window's close button was pressed; asks about unsaved files first.
    void request_close();
    bool should_close() const noexcept { return close_confirmed_; }
    void open_project(const std::filesystem::path& directory);
    // Text for the window title bar.
    std::string window_title() const;

private:
    struct Document {
        std::filesystem::path path;
        std::string title;
        TextEditor editor;
        std::size_t saved_undo_index = 0;
        bool keep_open = true;
        bool select = false;  // bring the tab to the front on the next frame
        bool dirty() const { return editor.GetUndoIndex() != saved_undo_index; }
    };

    // State of the account dialog and its background sign-in.
    struct SignIn {
        bool open = false;
        int mode = 0;  // 0: API key, 1: Apple ID
        bool accepted_warning = false;
        std::string key_id;
        std::string issuer_id;
        std::string key_path;
        std::string apple_id;
        std::string password;
        std::string code;

        std::jthread worker;
        std::mutex mutex;
        std::condition_variable wake;
        bool busy = false;
        bool finished = false;
        std::string status;
        std::string error;
        bool needs_code = false;
        bool code_is_sms = false;
        std::optional<std::string> code_reply;
        bool needs_team = false;
        std::vector<auth::Team> teams;
        std::optional<std::size_t> team_reply;
    };

    void apply_style();
    void handle_shortcuts();
    void draw_menu_bar();
    void draw_toolbar(const ImGuiViewport* viewport, float height);
    void draw_dock_space(const ImGuiViewport* viewport, float top);
    void draw_navigator();
    void draw_tree(const FileNode& node, int depth);
    void draw_editor();
    void draw_welcome();
    void draw_inspector();
    void draw_console();
    void draw_dialogs();
    void draw_sign_in();
    void draw_new_project();

    Document* current_document();
    void open_file(const std::filesystem::path& path, int line = -1);
    bool save(Document& document);
    void save_all();
    bool any_dirty() const;
    void show_message(std::string title, std::string text);
    void choose_and_open_project();
    void start_sign_in();
    void cancel_sign_in();
    void refresh_account();

    void* window_;
    Fonts fonts_;
    float scale_;
    Workspace workspace_;

    std::vector<std::unique_ptr<Document>> documents_;
    Document* active_ = nullptr;
    bool layout_built_ = false;

    // Console.
    int console_tab_ = 0;
    std::uint64_t seen_build_revision_ = 0;
    std::uint64_t seen_device_revision_ = 0;
    std::string device_log_filter_;
    bool stream_device_log_ = false;
    bool focus_issues_ = false;

    // Inspector.
    std::string account_summary_;
    std::string identity_summary_;
    bool signed_in_ = false;

    // Dialogs.
    SignIn sign_in_;
    bool new_project_open_ = false;
    std::string new_project_name_ = "Hello";
    std::string new_project_org_ = "com.example";
    std::string new_project_location_;
    std::string message_title_;
    std::string message_text_;
    bool message_pending_ = false;
    bool about_open_ = false;
    bool close_requested_ = false;
    bool close_confirmed_ = false;
};

}  // namespace winx::ide
