add_library(sha256 STATIC ./sha256.cpp ./tagged_hash.cpp ./merkle_root.cpp)
target_include_directories(sha256 PUBLIC ${CMAKE_SOURCE_DIR}/include)