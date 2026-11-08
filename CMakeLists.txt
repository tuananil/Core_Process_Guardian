cmake_minimum_required(VERSION 3.16)
project(CoreProcessGuardian CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /utf-8)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(guardian guardian.cpp)

enable_testing()
add_executable(test_guardian tests/test_guardian.cpp)
add_test(NAME test_guardian COMMAND test_guardian)
