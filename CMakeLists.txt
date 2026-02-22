cmake_minimum_required(VERSION 3.20)
project(synscan
    VERSION 0.1.0
    DESCRIPTION "Educational C++ SYN scanner (nmap -sS style)"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Platform: Linux — full raw-socket support")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    message(STATUS "Platform: macOS — raw-socket support (requires root)")
elseif(WIN32)
    message(FATAL_ERROR
        "Windows is not yet supported.\n"
        "Raw-socket SYN scanning requires Npcap or WinPcap, which is a\n"
        "fundamentally different API surface.  See README for architecture\n"
        "notes and the cross-platform status matrix.")
else()
    message(WARNING
        "Unknown platform '${CMAKE_SYSTEM_NAME}' — build may fail.\n"
        "cpp-synscan currently targets Linux and macOS.")
endif()

# Warnings — treat code quality seriously from day one.
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# ---------------------------------------------------------------------------
# Library: core scanner logic (linked by both the CLI binary and tests)
# ---------------------------------------------------------------------------
add_library(synscan_lib STATIC
    src/port_spec.cpp
    src/args.cpp
    src/output.cpp
    src/packet.cpp
    src/scanner.cpp
)
target_include_directories(synscan_lib PUBLIC include)

# ---------------------------------------------------------------------------
# CLI executable
# ---------------------------------------------------------------------------
add_executable(synscan src/main.cpp)
target_link_libraries(synscan PRIVATE synscan_lib)

# ---------------------------------------------------------------------------
# Tests (using a minimal single-header test approach — no external deps)
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
