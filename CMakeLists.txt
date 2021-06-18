cmake_minimum_required(VERSION 3.1.2)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

option(BUILD_TEST "Build the test program" ON)

if(EXISTS ${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup(TARGETS)
else()
    message(
        WARNING
            "The file conanbuildinfo.cmake doesn't exist, you have to run conan install first"
    )
endif()

add_library(base INTERFACE)
target_include_directories(base INTERFACE ${CMAKE_SOURCE_DIR}/include)
add_library(ocfbnj::base ALIAS base)
link_libraries(ocfbnj::base)

add_subdirectory(src)

if(BUILD_TEST)
    add_subdirectory(test)
endif()
