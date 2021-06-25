cmake_minimum_required(VERSION 3.16.3)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TEST "Build the test program" ON)

########### Conan Package Manager ###########################################################
#############################################################################################

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

# Add `find_package` here
find_package(asio)
find_package(cryptopp)
find_package(fmt)
find_package(spdlog)
find_package(GTest)

#############################################################################################
########### Conan Package Manager End #######################################################

include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(src)

if(BUILD_TEST)
    add_subdirectory(test)
endif()
