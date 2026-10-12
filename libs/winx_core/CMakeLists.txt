add_library(winx_core STATIC
    src/base64.cpp
    src/crypto.cpp
    src/der.cpp
    src/files.cpp
    src/http.cpp
    src/plist.cpp
    src/plist_binary.cpp
    src/plist_xml.cpp
    src/process.cpp
    src/socket.cpp
    src/text.cpp)
add_library(winx::core ALIAS winx_core)

target_include_directories(winx_core PUBLIC include)
target_link_libraries(winx_core
    PUBLIC winx_options
    PRIVATE ws2_32 bcrypt crypt32 winhttp shell32 ole32)
