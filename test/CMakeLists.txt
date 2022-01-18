if(TARGET GTest::gtest AND TARGET GTest::gtest_main)
    add_executable(test_crypto test_crypto.cpp)
    target_link_libraries(test_crypto PRIVATE GTest::gtest GTest::gtest_main ocfbnj::crypto)
endif()
