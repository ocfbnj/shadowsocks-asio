find_package(cryptopp CONFIG REQUIRED)

add_library(crypto AEAD.cpp)

target_link_libraries(crypto cryptopp-static)
target_include_directories(crypto INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(crypto PRIVATE ${CMAKE_SOURCE_DIR})

add_subdirectory(test)
