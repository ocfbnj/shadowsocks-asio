cmake_minimum_required(VERSION 3.16)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

find_package(asio CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

add_subdirectory(crypto)

list(APPEND LIBS
    asio::asio
    fmt::fmt
    spdlog::spdlog
    crypto)

list(APPEND SRC
    Connection.cpp
    EncryptedConnection.cpp
    Server.cpp
    socks5.cpp
    main.cpp)

add_executable(${CMAKE_PROJECT_NAME} ${SRC})

if(UNIX)
    target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fcoroutines)
endif(UNIX)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBS})
