find_package(GTest CONFIG)

if (GTest_FOUND)
    list(APPEND deps
        cryptopp
        
        GTest::gtest
        GTest::gtest_main)

    add_executable(test test.cpp
        ../AEAD.h
        ../AEAD.cpp
        ../ChaCha20Poly1305.h)
    target_link_libraries(test ${deps})
endif ()