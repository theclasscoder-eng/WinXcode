add_library(win_device_transport STATIC
    src/device_services.cpp
    src/lockdown.cpp
    src/pair_record.cpp
    src/tls.cpp
    src/usbmux.cpp)
add_library(winx::device_transport ALIAS win_device_transport)

target_include_directories(win_device_transport PUBLIC include)
target_link_libraries(win_device_transport
    PUBLIC winx::core
    PRIVATE shell32 ole32 secur32 crypt32 ncrypt)
