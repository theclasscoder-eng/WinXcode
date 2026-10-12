add_library(winx_engine STATIC
    src/pipeline.cpp
    src/sign_in.cpp)
add_library(winx::engine ALIAS winx_engine)

target_include_directories(winx_engine PUBLIC include)
target_link_libraries(winx_engine PUBLIC
    winx::core
    winx::device_transport
    winx::dev_auth
    winx::codesign
    winx::build_driver)
