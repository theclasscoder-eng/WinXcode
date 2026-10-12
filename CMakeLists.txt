cmake_minimum_required(VERSION 3.25)

project(WinXcode
    VERSION 0.1.0
    DESCRIPTION "Native Windows iOS development engine"
    LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "WinXcode targets native Windows only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(WINX_BUILD_TESTS "Build the unit tests" ON)

# Compile settings shared by every first-party target.
add_library(winx_options INTERFACE)
target_compile_definitions(winx_options INTERFACE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00)
if(MSVC)
    target_compile_options(winx_options INTERFACE
        /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP)
endif()

include(cmake/Dependencies.cmake)

add_subdirectory(libs/winx_core)
add_subdirectory(libs/win_device_transport)
add_subdirectory(libs/win_dev_auth)
add_subdirectory(libs/win_codesign)
add_subdirectory(libs/win_build_driver)
add_subdirectory(libs/winx_engine)
add_subdirectory(tools/ld64_shim)
add_subdirectory(tools/winx)
add_subdirectory(apps/win_ide)

if(WINX_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
