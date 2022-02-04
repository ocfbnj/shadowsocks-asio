add_executable(
    ${CMAKE_PROJECT_NAME}
    ACL.cpp
    Connection.cpp
    EncryptedConnection.cpp
    IPSet.cpp
    main.cpp
    ReplayProtection.cpp
    socks5.cpp
    tcp.cpp)

if(UNIX AND NOT APPLE)
    target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fcoroutines)
endif()

if(MSVC)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE _WIN32_WINNT=0x0601)
endif()

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE asio::asio fmt::fmt spdlog::spdlog ocfbnj::crypto ArashPartow::bloom)
