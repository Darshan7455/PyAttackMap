# C++ tests CMakeLists.txt

add_executable(pyattackmap_tests
    unit/test_models.cpp
    unit/test_parser.cpp
    unit/test_rules.cpp
    unit/test_dataflow.cpp
    unit/test_reporting.cpp
    integration/test_analyzer.cpp
    integration/test_cli.cpp
)

target_include_directories(pyattackmap_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(pyattackmap_tests PRIVATE
    pyattackmap_lib
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(pyattackmap_tests)

