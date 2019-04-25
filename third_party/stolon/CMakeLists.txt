cmake_minimum_required(VERSION 2.8)

project(stolon_support C)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE "Debug")
endif()
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    set(CMAKE_C_FLAGS "-std=gnu99 -Wall -Wextra -fPIC -g -O2")
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(CMAKE_C_FLAGS "-std=gnu99 -Wall -Wextra -fPIC -g -O0")
endif()

find_library(UUID_LIB uuid)

include_directories(sources)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../..)
include_directories(${MACHINARIUM_INCLUDE_DIRS})
include_directories(${CETCD_INCLUDE_DIRS})
set(library_name stolonstorage)
set(src sources/stolon_storage.c)

add_library(stolon_storage STATIC ${src})
set_target_properties(stolon_storage PROPERTIES OUTPUT_NAME ${library_name})

target_link_libraries(stolon_storage cetcd ${UUID_LIB})
add_dependencies(stolon_storage libcetcd)
