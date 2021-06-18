cmake_minimum_required(VERSION 3.1.2)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TEST "Build the test program" ON)

if(EXISTS ${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup(TARGETS)
else()
    message(WARNING "The file conanbuildinfo.cmake doesn't exist, you have to run conan install first")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(src)

if(BUILD_TEST)
    add_subdirectory(test)
endif()
