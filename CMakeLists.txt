cmake_minimum_required(VERSION 3.16.3)

project(shadowsocks-asio)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TEST "Build the test program" ON)

########### Conan Package Manager ###########################################################
#############################################################################################

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/v0.16.1/conan.cmake"
         "${CMAKE_BINARY_DIR}/conan.cmake"
         EXPECTED_HASH SHA256=396e16d0f5eabdc6a14afddbcfff62a54a7ee75c6da23f32f7a31bc85db23484
         TLS_VERIFY ON)
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

# Add requires here
conan_cmake_configure(
    REQUIRES
        asio/1.19.2
        cryptopp/8.5.0
        fmt/8.0.1
        spdlog/1.9.2
        sqlite3/3.36.0
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
find_package(asio)
find_package(cryptopp)
find_package(fmt)
find_package(spdlog)
find_package(GTest)
find_package(SQLite3)

#############################################################################################
########### Conan Package Manager End #######################################################

include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(src)

if(BUILD_TEST)
    add_subdirectory(test)
endif()
