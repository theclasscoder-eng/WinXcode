add_library(win_build_driver STATIC
    src/archive.cpp
    src/bundler.cpp
    src/ipa.cpp
    src/project.cpp
    src/sdk.cpp
    src/swiftpm.cpp)
add_library(winx::build_driver ALIAS win_build_driver)

target_include_directories(win_build_driver PUBLIC include)
# xz 5.6 exports its headers for installed use only; LZMA_API_STATIC stops
# lzma.h from declaring the functions as DLL imports.
target_include_directories(win_build_driver SYSTEM PRIVATE "${xz_SOURCE_DIR}/src/liblzma/api")
target_compile_definitions(win_build_driver PRIVATE LZMA_API_STATIC)
target_link_libraries(win_build_driver
    PUBLIC winx::core nlohmann_json::nlohmann_json
    PRIVATE miniz liblzma yaml-cpp::yaml-cpp windowscodecs ole32 shell32)
