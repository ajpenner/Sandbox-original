cmake_minimum_required (VERSION 3.0..3.14)

project (
  ltoTest
  CXX
)

include (
  colors
  OPTIONAL
)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

add_compile_options (
  -Wall
  -Wextra
  -Wpedantic
  -Werror
  -Wfloat-equal
  -Wconversion
  -Wcast-qual
  -Wno-unknown-pragmas
  -pedantic-errors
  # -Wcast-align // AJP_TODO: I do not know how to fix all the problems this
  # generates yet
  -Wdisabled-optimization
  # -Wstrict-overflow=3 // This is a particularly messy warning to enforce, need
  # to develop a plan first
  -Wformat=2
  -Wredundant-decls
  -Wmissing-include-dirs
  -Wshadow
  -Wnull-dereference
  # Boost headers conflict with this directive
  # $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-branches>
  $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-cond>
  $<$<CXX_COMPILER_ID:GNU>:-Wlogical-op>
)

message (
  "Compiler ID: "
  ${CMAKE_CXX_COMPILER_ID}
)

cmake_policy(SET CMP0069 NEW) 
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)

set (
    LIBRARY_SOURCES
    ${PROJECT_SOURCE_DIR}/donothing.cpp
)

set(LTO "LTO")

add_library (
    ${LTO}
  STATIC
  ${LIBRARY_SOURCES}
)

if( supported )
    message(STATUS "IPO / LTO enabled")
    # The following line set LTO/IPO for a specific target
    set_property(TARGET ${LTO} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    # The following line sets LTO/IPO for all targets after this line
    # set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

set (
    MAIN_SOURCES
    ${PROJECT_SOURCE_DIR}/main.cpp
)

set(MAIN "cmakeTest")

add_executable (
    ${MAIN}
  ${MAIN_SOURCES}
)

target_link_libraries (
    ${MAIN}
    PRIVATE LTO
          )

if( supported )
    message(STATUS "IPO / LTO enabled")
    # The following line set LTO/IPO for a specific target
    set_property(TARGET ${MAIN} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    # The following line sets LTO/IPO for all targets after this line
    # set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

