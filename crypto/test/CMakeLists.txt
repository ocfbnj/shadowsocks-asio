find_package(GTest CONFIG)

if (GTest_FOUND)
    add_executable(test test.cpp)
    target_link_libraries(test crypto GTest::gtest GTest::gtest_main)
    target_include_directories(test PRIVATE ${CMAKE_SOURCE_DIR})
endif ()