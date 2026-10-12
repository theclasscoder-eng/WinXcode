# Stands in for swift.exe in the build-driver tests.
add_executable(fake_swift fake_swift.cpp)

add_executable(winx_tests
    apple_id_tests.cpp
    auth_tests.cpp
    build_tests.cpp
    codesign_tests.cpp
    core_tests.cpp
    device_tests.cpp
    fake_device.cpp
    ide_tests.cpp
    pair_record_tests.cpp
    plist_tests.cpp
    support.cpp
    usbmux_tests.cpp)

target_link_libraries(winx_tests PRIVATE
    winx::engine
    win_ide_core
    Catch2::Catch2WithMain
    miniz liblzma
    crypt32 ncrypt)
target_include_directories(winx_tests SYSTEM PRIVATE "${xz_SOURCE_DIR}/src/liblzma/api")
target_compile_definitions(winx_tests PRIVATE
    LZMA_API_STATIC
    WINX_FAKE_SWIFT_PATH="$<TARGET_FILE:fake_swift>")
add_dependencies(winx_tests fake_swift)

include(Catch)
catch_discover_tests(winx_tests)
