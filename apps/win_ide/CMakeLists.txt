# Dear ImGui and the text editor widget, compiled from their fetched sources.
add_library(winx_imgui STATIC
    "${imgui_SOURCE_DIR}/imgui.cpp"
    "${imgui_SOURCE_DIR}/imgui_draw.cpp"
    "${imgui_SOURCE_DIR}/imgui_tables.cpp"
    "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp"
    "${imgui_SOURCE_DIR}/misc/cpp/imgui_stdlib.cpp"
    "${imgui_text_edit_SOURCE_DIR}/TextEditor.cpp")
target_include_directories(winx_imgui SYSTEM PUBLIC
    "${imgui_SOURCE_DIR}"
    "${imgui_SOURCE_DIR}/backends"
    "${imgui_SOURCE_DIR}/misc/cpp"
    "${imgui_text_edit_SOURCE_DIR}")
target_compile_features(winx_imgui PUBLIC cxx_std_20)
target_compile_definitions(winx_imgui PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
if(MSVC)
    target_compile_options(winx_imgui PRIVATE /utf-8 /W3 /MP)
endif()
target_link_libraries(winx_imgui PUBLIC d3d11 dxgi d3dcompiler dwmapi)

# Everything about the IDE that is not drawing, so it can be tested.
add_library(win_ide_core STATIC
    src/swift_language.cpp
    src/workspace.cpp)
target_include_directories(win_ide_core PUBLIC src)
target_link_libraries(win_ide_core PUBLIC winx::engine winx_imgui)

add_executable(winxcode WIN32
    src/ide_app.cpp
    src/main.cpp
    src/platform.cpp)
target_link_libraries(winxcode PRIVATE win_ide_core ole32 shell32 uuid)
