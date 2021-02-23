cmake_minimum_required(VERSION 3.16)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED coroutine)
find_library(CryptoPP libcryptopp.a)

list(APPEND deps
    cryptopp
    Boost::coroutine)

list(APPEND src
    socks5.cpp
    io.cpp
    Connection.cpp
    EncryptedConnection.cpp
    Server.cpp
    AEAD.cpp
    main.cpp)

add_executable(shadowsocks-asio ${src})

target_include_directories(shadowsocks-asio PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(shadowsocks-asio PUBLIC ${deps})

add_subdirectory(test)
