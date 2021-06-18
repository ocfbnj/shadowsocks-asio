if(TARGET CONAN_PKG::gtest)
    add_executable(test_crypto test_crypto.cpp)
    target_link_libraries(
        test_crypto PRIVATE CONAN_PKG::gtest CONAN_PKG::cryptopp ocfbnj::crypto)
endif()
