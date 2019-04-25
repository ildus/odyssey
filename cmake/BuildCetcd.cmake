macro(build_cetcd)
	set(CETCD_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/third_party/cetcd)
	add_custom_command(
		OUTPUT  ${PROJECT_BINARY_DIR}/third_party/cetcd/libcetcd.so
		COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/third_party/cetcd
		COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/third_party/cetcd ${PROJECT_BINARY_DIR}/third_party/cetcd
		COMMAND cd ${PROJECT_BINARY_DIR}/third_party/cetcd && make
	)
	add_custom_target(libcetcd ALL
		DEPENDS ${PROJECT_BINARY_DIR}/third_party/cetcd/libcetcd.so
	)
	message(STATUS "Use shipped libcetcd: ${PROJECT_SOURCE_DIR}/third_party/cetcd")
	set (CETCD_LIBRARIES "${PROJECT_BINARY_DIR}/third_party/cetcd/libcetcd.so")
	add_dependencies(build_libs libcetcd)
endmacro(build_cetcd)
