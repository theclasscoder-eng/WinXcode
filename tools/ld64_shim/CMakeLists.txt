add_executable(winx-ld64-shim main.cpp)
target_link_libraries(winx-ld64-shim PRIVATE winx::core)
