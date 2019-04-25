cmake_minimum_required(VERSION 3.5)
project(libstolonstorage VERSION 1.0.0 LANGUAGES C)

set(src src/stolon_storage.c)

add_library(stolon_storage STATIC ${src})
target_compile_options(stolon_storage PRIVATE -Werror -Wall -Wextra)
target_compile_features(stolon_storage PRIVATE c_std_11)

find_package(PkgConfig)
pkg_check_modules(JANSSON jansson REQUIRED)
pkg_check_modules(UUID uuid REQUIRED)

target_include_directories(stolon_storage
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/../..
		${MACHINARIUM_INCLUDE_DIRS}
		${CETCD_INCLUDE_DIRS}
)

target_link_libraries(stolon_storage ${CETCD_LIBRARIES} ${JANSSON_LIBRARIES} ${UUID_LIBRARIES})
add_dependencies(stolon_storage libcetcd)
