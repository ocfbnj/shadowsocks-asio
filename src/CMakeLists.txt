add_executable(
    ${CMAKE_PROJECT_NAME}
    access_control_list.cpp
    config.cpp
    connection.cpp
    convert.cpp
    encrypted_connection.cpp
    ip_set.cpp
    main.cpp
    replay_protection.cpp
    socks5.cpp
    ss_url.cpp
    tcp.cpp)

if(UNIX AND NOT APPLE)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fcoroutines)
    endif()
endif()

if(MSVC)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE _WIN32_WINNT=0x0601)
endif()

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE asio::asio fmt::fmt spdlog::spdlog ocfbnj::crypto ArashPartow::bloom)
