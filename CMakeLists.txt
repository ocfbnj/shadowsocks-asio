cmake_minimum_required(VERSION 3.16)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

find_package(asio CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(cryptopp CONFIG REQUIRED)

list(APPEND LIBS
    asio::asio
    spdlog::spdlog
    cryptopp-static)

list(APPEND SRC
    Connection.cpp
    EncryptedConnection.cpp
    Server.cpp
    AEAD.cpp
    main.cpp)

add_executable(${CMAKE_PROJECT_NAME} ${SRC})

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fcoroutines)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${LIBS})

add_subdirectory(test)
