cmake_minimum_required(VERSION 3.20)
project(PoliceSimUnlocker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT MSVC)
    message(FATAL_ERROR "MSVC toolchain is required.")
endif()

add_executable(PoliceSimUnlocker src/PoliceSimUnlocker.cpp)
target_compile_options(PoliceSimUnlocker PRIVATE /W4 /permissive-)
target_link_libraries(PoliceSimUnlocker PRIVATE advapi32 user32 psapi)

string(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
add_library(library SHARED library/src/library.cpp)
target_compile_options(library PRIVATE /W4 /permissive- /EHs-c-)
target_link_options(library PRIVATE /MANIFEST:NO /DEBUG:NONE)
target_link_libraries(library PRIVATE psapi)
