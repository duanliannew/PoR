add_library(por STATIC ./sha256.cpp ./tagged_hash.cpp ./merkle_root.cpp ./por_db.cpp ./merkle_proof.cpp ./wrapper.cpp)
target_include_directories(por PUBLIC ${CMAKE_SOURCE_DIR}/include)