cmake_minimum_required(VERSION 2.8.9)
project (fakeit_test)

# Catch2 is installed globally
find_package(Catch2 CONFIG REQUIRED) # Catch_INCLUDE_DIR

#FakeIt is not installable
set(FAKEIT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fakeit)
add_library(FakeIt INTERFACE)
#target_link_libraries()

file(GLOB_RECURSE sources fakeittest.cpp)

add_executable(faketest ${sources})

# Catch2 or FakeIt require C++11 features, so we set the compiler to use them
# I would encourage the use of Wall which enables all warnings
# Furthermore, with Wall I encourage the use of -Werror that converts warnings to errors
# Note: if some warnings are unmanageable (i.e. from a third party lib) 
#		they can be supressed with pragmas
# FakeIt report that they cannot handle -O3 level optimisation, -O3 is preferred for a release build
# 	-O0 is the default optimisation and should be considered "Debug" in MSVC parlance
target_compile_options(faketest PRIVATE -std=c++11 -Wall -Werror -O2)

target_include_directories(faketest PRIVATE ~/GitRepos/FakeIt/single_header/catch)
target_include_directories(faketest PRIVATE ~/GitRepos/FakeIt/include)
target_include_directories(faketest PRIVATE ${Catch_INCLUDE_DIR})


install(TARGETS faketest DESTINATION ~/bin)
