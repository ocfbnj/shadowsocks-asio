add_library(crypto STATIC AEAD.cpp)
target_include_directories(crypto PRIVATE ${CMAKE_SOURCE_DIR}/include/crypto)
target_link_libraries(crypto PUBLIC cryptopp::cryptopp)

add_library(ocfbnj::crypto ALIAS crypto)
