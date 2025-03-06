add_library(sha256 STATIC ./sha256.cpp ./tagged_hash.cpp ./merkle_root.cpp ./por_db.cpp ./merkle_proof.cpp)
target_include_directories(sha256 PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(por_service ./por_service.cpp ./por_db.cpp)
target_include_directories(por_service PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(por_service PRIVATE sha256)