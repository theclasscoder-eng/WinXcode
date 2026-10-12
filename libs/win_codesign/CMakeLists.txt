add_library(win_codesign STATIC
    src/bundle.cpp
    src/codesign.cpp
    src/macho.cpp)
add_library(winx::codesign ALIAS win_codesign)

target_include_directories(win_codesign PUBLIC include)
target_link_libraries(win_codesign
    PUBLIC winx::core
    PRIVATE crypt32 ncrypt)
