cmake_minimum_required(VERSION 3.15)

if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

# Set policies for more modern cmake
cmake_policy(SET CMP0091 NEW) # Runtime flags
cmake_policy(SET CMP0092 NEW) # Warning flags

project(sockmeter)

# Use static CRT
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(sockmeter sockmeter.c)
target_include_directories(sockmeter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(sockmeter PUBLIC /WX /W4 /sdl /permissive- /guard:cf /Zi)
target_compile_definitions(sockmeter
  PUBLIC
    UNICODE _UNICODE
  PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
)
target_link_libraries(sockmeter PUBLIC ws2_32)
target_link_options(sockmeter PUBLIC /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG:FULL)

add_executable(stats_test stats_test.c)
target_include_directories(stats_test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(stats_test PUBLIC /WX /W4 /sdl /permissive- /guard:cf /Zi)
target_compile_definitions(stats_test PUBLIC UNICODE _UNICODE)
target_link_options(stats_test PUBLIC /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG:FULL)
