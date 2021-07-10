cmake_minimum_required(VERSION 3.0)
project (objectid)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug
        CACHE STRING "Set build type to Debug o Release (default Debug)" FORCE)
endif()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    # Force to always compile with W4
    if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    else()
        add_compile_options("/W4")
    endif()
else()
    # Update if necessary
    add_compile_options("-Wall" "-Wextra" "-Wno-long-long" "-pedantic")
endif()

add_executable(objectid_tests
    objectid_tests.cc
    objectid.hpp
)
