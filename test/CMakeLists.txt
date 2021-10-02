if(TARGET GTest::gtest AND TARGET GTest::gtest_main)
    link_libraries(GTest::gtest GTest::gtest_main fmt::fmt)

    add_executable(test_crypto test_crypto.cpp)
    target_include_directories(test_crypto PRIVATE ${CMAKE_SOURCE_DIR}/include/crypto)
    target_link_libraries(test_crypto PRIVATE ocfbnj::crypto)

    add_executable(test_sqlitepp test_sqlitepp.cpp)
    target_include_directories(test_sqlitepp PRIVATE ${CMAKE_SOURCE_DIR}/include/sqlitepp)
    target_link_libraries(test_sqlitepp PRIVATE ocfbnj::sqlitepp)
endif()
