add_subdirectory(crypto)

list(APPEND LIBS asio::asio fmt::fmt spdlog::spdlog crypto)

add_executable(${CMAKE_PROJECT_NAME} Connection.cpp EncryptedConnection.cpp
                                     socks5.cpp tcp.cpp main.cpp)
if(UNIX)
    target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fcoroutines)
endif(UNIX)
target_link_libraries(
    ${CMAKE_PROJECT_NAME} PRIVATE CONAN_PKG::asio CONAN_PKG::fmt
                                  CONAN_PKG::spdlog ocfbnj::crypto)
