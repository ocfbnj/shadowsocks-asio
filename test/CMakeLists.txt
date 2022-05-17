if(TARGET GTest::gtest AND TARGET GTest::gtest_main)
    add_executable(test_ssurl test_ssurl.cpp ../src/ss_url.cpp)
    target_link_libraries(test_ssurl ocfbnj::crypto GTest::gtest GTest::gtest_main)

    add_executable(test_ip_set test_ip_set.cpp ../src/ip_set.cpp)
    target_link_libraries(test_ip_set asio::asio GTest::gtest GTest::gtest_main)
    
    add_executable(test_rule_set test_rule_set.cpp ../src/rule_set.cpp)
    target_link_libraries(test_rule_set GTest::gtest GTest::gtest_main)
endif()
