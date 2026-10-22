cmake_minimum_required(VERSION 3.20)

project(PyAttackMap
    VERSION 0.2.0
    DESCRIPTION "Explainable Static Security Analysis and Data-Flow Visualization Library for Python"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimization and warning flags
if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)

# 1. Tree-sitter core
message(STATUS "Configuring tree-sitter core...")
FetchContent_Declare(
    tree_sitter
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter.git
    GIT_TAG v0.24.7
)
FetchContent_GetProperties(tree_sitter)
if(NOT tree_sitter_POPULATED)
    FetchContent_Populate(tree_sitter)
    add_library(tree-sitter STATIC "${tree_sitter_SOURCE_DIR}/lib/src/lib.c")
    target_include_directories(tree-sitter PUBLIC "${tree_sitter_SOURCE_DIR}/lib/include")
    target_include_directories(tree-sitter PRIVATE "${tree_sitter_SOURCE_DIR}/lib/src")
    set_target_properties(tree-sitter PROPERTIES C_STANDARD 11)
endif()

# 2. Tree-sitter Python grammar
message(STATUS "Configuring tree-sitter Python grammar...")
FetchContent_Declare(
    tree_sitter_python
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-python.git
    GIT_TAG v0.23.6
)
FetchContent_GetProperties(tree_sitter_python)
if(NOT tree_sitter_python_POPULATED)
    FetchContent_Populate(tree_sitter_python)
    add_library(tree-sitter-python STATIC
        "${tree_sitter_python_SOURCE_DIR}/src/parser.c"
        "${tree_sitter_python_SOURCE_DIR}/src/scanner.c"
    )
    target_include_directories(tree-sitter-python PUBLIC "${tree_sitter_python_SOURCE_DIR}/src")
    target_link_libraries(tree-sitter-python PUBLIC tree-sitter)
    set_target_properties(tree-sitter-python PROPERTIES C_STANDARD 11)
endif()

# 3. nlohmann/json
message(STATUS "Configuring nlohmann_json...")
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)

# 4. GoogleTest
message(STATUS "Configuring googletest...")
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
FetchContent_MakeAvailable(googletest)

# Library sources
set(PYATTACKMAP_SOURCES
    src/parser.cpp
    src/reporting.cpp
    src/analyzer.cpp
    src/dataflow/sources.cpp
    src/dataflow/sinks.cpp
    src/dataflow/sanitizers.cpp
    src/dataflow/engine.cpp
    src/rules/registry.cpp
    src/rules/sql_injection.cpp
    src/rules/command_injection.cpp
    src/rules/unsafe_deserialization.cpp
)

# Core PyAttackMap library
add_library(pyattackmap_lib STATIC ${PYATTACKMAP_SOURCES})
target_include_directories(pyattackmap_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(pyattackmap_lib PUBLIC
    $<BUILD_INTERFACE:tree-sitter>
    $<BUILD_INTERFACE:tree-sitter-python>
    $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
)

# CLI executable
add_executable(pyattackmap src/cli.cpp)
target_link_libraries(pyattackmap PRIVATE pyattackmap_lib)

# Benchmark executable
add_executable(pyattackmap_bench benchmarks/bench_main.cpp)
target_link_libraries(pyattackmap_bench PRIVATE pyattackmap_lib)

# Testing
enable_testing()
add_subdirectory(tests)

# Installation rules
include(GNUInstallDirs)
install(TARGETS pyattackmap_lib pyattackmap
    EXPORT PyAttackMapTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT PyAttackMapTargets
    FILE PyAttackMapTargets.cmake
    NAMESPACE pyattackmap::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PyAttackMap
)

