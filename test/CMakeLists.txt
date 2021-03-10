find_package(GTest CONFIG)

if (GTest_FOUND)
    find_package(cryptopp CONFIG REQUIRED)

    list(APPEND LIBS
        cryptopp-static
        GTest::gtest
        GTest::gtest_main)

    add_executable(test test.cpp
        ../AEAD.h
        ../AEAD.cpp
        ../ChaCha20Poly1305.h)
    target_link_libraries(test PRIVATE ${LIBS})
endif ()