add_library(crypto STATIC AEAD.cpp crypto.cpp)
target_include_directories(crypto PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(crypto PUBLIC cryptopp::cryptopp)

add_library(ocfbnj::crypto ALIAS crypto)
