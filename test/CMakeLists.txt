include(GoogleTest)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	if(NOT DEFINED GTEST_LIBRARY)
		FetchContent_Declare(
				googletest
				GIT_REPOSITORY https://github.com/google/googletest.git
				GIT_TAG        release-1.8.0
		)

		FetchContent_GetProperties(googletest)
		if(NOT googletest_POPULATED)
			FetchContent_Populate(googletest)
			add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR})
		endif()

	endif()
endif()


mark_as_advanced(
		BUILD_GMOCK BUILD_GTEST BUILD_SHARED_LIBS
		gmock_build_tests  gtest_build_tests
		gtest_disable_pthreads gtest_force_shared_crt gtest_hide_internal_symbols
)

set_target_properties(gtest PROPERTIES FOLDER build)
set_target_properties(gtest_main PROPERTIES FOLDER build)
set_target_properties(gmock PROPERTIES FOLDER build)
set_target_properties(gmock_main PROPERTIES FOLDER build)
# back out of test directory for current working directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../bin)

macro(package_add_test TESTNAME)
	# create an exectuable in which the tests will be stored
	add_executable(${TESTNAME} ${ARGN})
	# link the Google test infrastructure, mocking library, and a default main fuction to
	# the test executable.  Remove g_test_main if writing your own main function.
	target_link_libraries(${TESTNAME}  gtest  gmock  vaultdb-emp)
	# gtest_discover_tests replaces gtest_add_tests,
	# see https://cmake.org/cmake/help/v3.10/module/GoogleTest.html for more options to pass to it
	gtest_discover_tests(${TESTNAME}
			# set a working directory so your project root so that you can find test data via paths relative to the project root
			WORKING_DIRECTORY ${PROJECT_DIR}
			PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${PROJECT_DIR}" LABELS ${Labels}
			DISCOVERY_MODE PRE_TEST)
	set_target_properties(${TESTNAME} PROPERTIES FOLDER bin)
endmacro()

set(Labels "LABELS;FheTest")

# FHE tests (OpenFHE-based)
package_add_test(fhe_table_scan_test fhe/fhe_table_scan_test.cpp fhe/fhe_base_test.cpp)
package_add_test(fhe_filter_test fhe/fhe_filter_test.cpp fhe/fhe_base_test.cpp)
package_add_test(fhe_aggregate_test fhe/fhe_aggregate_test.cpp fhe/fhe_base_test.cpp)
package_add_test(fhe_tpch_test fhe/fhe_tpch_test.cpp fhe/fhe_base_test.cpp ../util/fhe/fhe_mpc_party_a.cpp)
if(GPERFTOOLS_PROFILER_LIB)
	target_link_libraries(fhe_tpch_test ${GPERFTOOLS_PROFILER_LIB})
endif()
package_add_test(fhe_plan_parser_test fhe/fhe_plan_parser_test.cpp fhe/fhe_base_test.cpp)

# MPC comparison test (EMP-based, for E6 baseline)
package_add_test(mpc_comparison_test fhe/mpc_comparison_test.cpp mpc/emp_base_test.cpp)

# GPU FHE tests (HEonGPU)
if(ENABLE_GPU)
    package_add_test(gpu_fhe_filter_test fhe/gpu_fhe_filter_test.cpp)
    package_add_test(gpu_fhe_tpch_test fhe/gpu_fhe_tpch_test.cpp)
endif()

unset(Labels)

add_custom_target(unit_tests ALL)
add_dependencies(unit_tests fhe_tpch_test fhe_filter_test fhe_aggregate_test fhe_table_scan_test fhe_plan_parser_test mpc_comparison_test)
