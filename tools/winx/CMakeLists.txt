add_executable(winx
    src/auth_command.cpp
    src/build_command.cpp
    src/devices_command.cpp
    src/ds_command.cpp
    src/install_command.cpp
    src/main.cpp
    src/sign_command.cpp)

target_link_libraries(winx PRIVATE
    winx::engine
    CLI11::CLI11)

# The SDK installer copies the linker shim from next to winx.exe.
add_dependencies(winx winx-ld64-shim)
