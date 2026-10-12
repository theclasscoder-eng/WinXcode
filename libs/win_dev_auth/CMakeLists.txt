add_library(win_dev_auth STATIC
    src/anisette.cpp
    src/apple_certs.cpp
    src/auth_session.cpp
    src/developer_api.cpp
    src/grandslam.cpp
    src/identity.cpp
    src/keys.cpp
    src/provisioner.cpp
    src/provisioning_profile.cpp
    src/srp.cpp
    src/xcode_transport.cpp)
add_library(winx::dev_auth ALIAS win_dev_auth)

target_include_directories(win_dev_auth PUBLIC include)
target_link_libraries(win_dev_auth
    PUBLIC winx::core nlohmann_json::nlohmann_json
    PRIVATE crypt32 ncrypt bcrypt)
