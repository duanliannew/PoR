cmake_minimum_required(VERSION 3.30)
project(PoR VERSION 0.9
            DESCRIPTION "PoR Implementation"
            LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MODULE_CMAKE_DIR ${CMAKE_SOURCE_DIR}/cmake)
list(APPEND CMAKE_MODULE_PATH ${MODULE_CMAKE_DIR})

add_custom_target(
    format
    ALL
    COMMAND clang-format-19
            -style=google 
            -i ${CMAKE_SOURCE_DIR}/src/*.cpp ${CMAKE_SOURCE_DIR}/include/*.h
               ${CMAKE_SOURCE_DIR}/test/*.cpp
)

add_subdirectory(src)
add_subdirectory(test)

add_custom_target(
    test
    COMMAND ./test/por_test
)

add_dependencies(test por_test)


