# Third-party dependencies, fetched at configure time and pinned to release tags.
# Later phases add their own entries here (Dear ImGui, nlohmann/json, yaml-cpp,
# liblzma, zlib, Mbed TLS).

include(FetchContent)

FetchContent_Declare(CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.4.2
    GIT_SHALLOW TRUE
    SYSTEM)
FetchContent_MakeAvailable(CLI11)

set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE
    SYSTEM)
FetchContent_MakeAvailable(nlohmann_json)

# zlib-compatible inflate/deflate, for the xar table of contents in Xcode.xip.
FetchContent_Declare(miniz
    GIT_REPOSITORY https://github.com/richgel999/miniz.git
    GIT_TAG 3.0.2
    GIT_SHALLOW TRUE
    SYSTEM
    EXCLUDE_FROM_ALL)
set(BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(BUILD_FUZZERS OFF CACHE INTERNAL "")
set(INSTALL_PROJECT OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(miniz)

# LZMA decoder for the pbzx payload of Xcode.xip. Windows has no LZMA API.
# 5.6.3 postdates the compromised 5.6.0/5.6.1 release tarballs.
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(XZ_NLS OFF CACHE INTERNAL "")
# Keeps xz's own test programs out of this project's CTest run.
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(xz
    GIT_REPOSITORY https://github.com/tukaani-project/xz.git
    GIT_TAG v5.6.3
    GIT_SHALLOW TRUE
    SYSTEM
    EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(xz)

set(YAML_CPP_BUILD_TESTS OFF CACHE INTERNAL "")
set(YAML_CPP_BUILD_TOOLS OFF CACHE INTERNAL "")
set(YAML_CPP_BUILD_CONTRIB OFF CACHE INTERNAL "")
set(YAML_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
FetchContent_Declare(yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG 0.8.0
    GIT_SHALLOW TRUE
    SYSTEM
    EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(yaml-cpp)

# Dear ImGui (docking branch) ships no build files; the target is defined in
# apps/win_ide/CMakeLists.txt from these sources.
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.92.9b-docking
    GIT_SHALLOW TRUE)
FetchContent_Populate(imgui)

# No release tags upstream; pinned to the commit this was developed against.
# It needs Dear ImGui 1.92 or newer.
FetchContent_Declare(imgui_text_edit
    GIT_REPOSITORY https://github.com/goossens/ImGuiColorTextEdit.git
    GIT_TAG 62be2ff651a4736d1c7236ae064e6f9bf1921d97)
FetchContent_Populate(imgui_text_edit)

if(WINX_BUILD_TESTS)
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.7.1
        GIT_SHALLOW TRUE
        SYSTEM)
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
endif()
