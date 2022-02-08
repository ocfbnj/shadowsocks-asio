if(TARGET GTest::gtest AND TARGET GTest::gtest_main)
    add_executable(test_ssurl test_ssurl.cpp ../src/SSURL.cpp)
    target_link_libraries(test_ssurl ocfbnj::crypto GTest::gtest GTest::gtest_main)
endif()
