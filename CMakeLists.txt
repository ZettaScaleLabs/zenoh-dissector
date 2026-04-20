cmake_minimum_required(VERSION 3.15)
project(packet-zenoh C)

# ---------------------------------------------------------------------------
# Wireshark plugin requirements
# ---------------------------------------------------------------------------

# Locate Wireshark headers and library.
# find_package(Wireshark) uses cmake config mode but on NixOS the dev and
# runtime outputs are split across two store paths, so the config file's
# imported target references a path that doesn't exist in the dev output.
# Work around by locating headers and lib directly.
find_path(Wireshark_INCLUDE_DIRS wireshark.h
    PATH_SUFFIXES wireshark
    REQUIRED)
find_library(Wireshark_LIBRARIES wireshark REQUIRED)
message(STATUS "Wireshark: include=${Wireshark_INCLUDE_DIRS} lib=${Wireshark_LIBRARIES}")

# GLib is a Wireshark dependency not always transitively exposed
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)

# ---------------------------------------------------------------------------
# Rust cdylib path (built separately with: cargo build -p zenoh-codec-ffi)
# Default to debug build; override with -DZENOH_CODEC_FFI_LIB=...
# ---------------------------------------------------------------------------

if(NOT DEFINED ZENOH_CODEC_FFI_LIB)
    if(WIN32)
        set(ZENOH_CODEC_FFI_LIB "${CMAKE_SOURCE_DIR}/target/debug/zenoh_codec_ffi.dll")
    elseif(APPLE)
        set(ZENOH_CODEC_FFI_LIB "${CMAKE_SOURCE_DIR}/target/debug/libzenoh_codec_ffi.dylib")
    else()
        set(ZENOH_CODEC_FFI_LIB "${CMAKE_SOURCE_DIR}/target/debug/libzenoh_codec_ffi.so")
    endif()
endif()

# ---------------------------------------------------------------------------
# C plugin target
# ---------------------------------------------------------------------------

add_library(packet-zenoh MODULE packet-zenoh.c)

# Wireshark plugins must not have a "lib" prefix
set_target_properties(packet-zenoh PROPERTIES PREFIX "")

target_include_directories(packet-zenoh PRIVATE
    ${Wireshark_INCLUDE_DIRS}
    ${GLIB2_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}
)

target_compile_options(packet-zenoh PRIVATE
    -Wall -Wextra
    # Wireshark headers use designated initialisers in C99/C11
    $<$<C_COMPILER_ID:GNU,Clang>:-std=c11>
)

target_link_libraries(packet-zenoh PRIVATE
    ${Wireshark_LIBRARIES}
    ${ZENOH_CODEC_FFI_LIB}
)

# ---------------------------------------------------------------------------
# Install to user plugin directory
# ---------------------------------------------------------------------------

if(NOT DEFINED WIRESHARK_PLUGIN_DIR)
    # Determine from Wireshark version
    execute_process(
        COMMAND tshark --version
        OUTPUT_VARIABLE TSHARK_VERSION_OUTPUT
        ERROR_QUIET
    )
    string(REGEX MATCH "([0-9]+\\.[0-9]+)" WS_MAJOR_MINOR "${TSHARK_VERSION_OUTPUT}")
    if(WIN32)
        set(WIRESHARK_PLUGIN_DIR "$ENV{APPDATA}/Wireshark/plugins/${WS_MAJOR_MINOR}/epan")
    else()
        set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins/${WS_MAJOR_MINOR}/epan")
    endif()
endif()

install(TARGETS packet-zenoh
        LIBRARY DESTINATION "${WIRESHARK_PLUGIN_DIR}"
        RUNTIME DESTINATION "${WIRESHARK_PLUGIN_DIR}")
