cmake_minimum_required(VERSION 3.16.3)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

########### Conan Package Manager ###########################################################
#############################################################################################

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake"
         "${CMAKE_BINARY_DIR}/conan.cmake"
         TLS_VERIFY ON)
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

# Add requires here
conan_cmake_configure(
    REQUIRES
        asio/1.22.1
        mbedtls/3.1.0
        fmt/8.1.1
        spdlog/1.10.0
        gtest/cci.20210126
    GENERATORS
        cmake_find_package)

conan_cmake_autodetect(settings)
conan_cmake_install(
    PATH_OR_REFERENCE .
    BUILD missing
    REMOTE conancenter
    SETTINGS ${settings})

# Add `find_package` here
find_package(asio REQUIRED)
find_package(MbedTLS REQUIRED)
find_package(fmt REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest)

#############################################################################################
########### Conan Package Manager End #######################################################

add_subdirectory(libs/crypto/src)
add_subdirectory(libs/bloom)

add_subdirectory(src)
add_subdirectory(test)
