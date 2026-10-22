.PHONY: build test clean bench install help

BUILD_DIR ?= build/release

help:
	@echo "PyAttackMap C++20 Build Targets:"
	@echo "  build     Build PyAttackMap library and CLI (Release mode)"
	@echo "  test      Run test suite with CTest"
	@echo "  bench     Run performance benchmark suite"
	@echo "  clean     Remove build directory and temporary files"
	@echo "  install   Install PyAttackMap to system/prefix"

build:
	cmake -B $(BUILD_DIR) -G Ninja -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR)

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

bench: build
	python benchmarks/run_cpp_benchmark.py

clean:
	cmake -E rm -rf build

install: build
	cmake --install $(BUILD_DIR)
