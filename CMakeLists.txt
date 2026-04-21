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
# On Windows, Wireshark headers live in the source tree built by
# scripts/build-wireshark-windows.ps1; libs are in the build run/ dir.
if(WIN32)
    file(GLOB _WS_SRC_DIRS "C:/wsbuild/wireshark-*")
    list(FILTER _WS_SRC_DIRS EXCLUDE REGEX "libs")
    find_path(Wireshark_INCLUDE_DIRS wireshark.h
        HINTS ${_WS_SRC_DIRS} "C:/wsbuild/build"
        REQUIRED)
    find_library(Wireshark_LIBRARIES wireshark
        HINTS "C:/wsbuild/build/run/Release" "C:/wsbuild/build/run/Debug"
        REQUIRED)
else()
    find_path(Wireshark_INCLUDE_DIRS wireshark.h
        PATH_SUFFIXES wireshark
        REQUIRED)
    find_library(Wireshark_LIBRARIES wireshark REQUIRED)
endif()
message(STATUS "Wireshark: include=${Wireshark_INCLUDE_DIRS} lib=${Wireshark_LIBRARIES}")

# GLib is a Wireshark dependency not always transitively exposed.
# On Windows glib ships inside Wireshark's win64-libs bundle; on Linux/macOS
# pkg-config finds it from the system package.
if(WIN32)
    # Wireshark's cmake build downloads win64-libs into C:\wsbuild\wireshark-win64-libs-*
    file(GLOB _WS_LIBS_DIRS "C:/wsbuild/wireshark-win64-libs-*")
    find_path(GLIB2_INCLUDE_DIRS glib.h
        HINTS ${_WS_LIBS_DIRS}
        PATH_SUFFIXES
            vcpkg-export/x64-windows/include/glib-2.0
            include/glib-2.0
        REQUIRED)
    # glib has a generated glibconfig.h in a sibling lib dir
    find_path(_GLIB_CONFIG_DIR glibconfig.h
        HINTS ${_WS_LIBS_DIRS}
        PATH_SUFFIXES
            vcpkg-export/x64-windows/lib/glib-2.0/include
            lib/glib-2.0/include
        REQUIRED)
    list(APPEND GLIB2_INCLUDE_DIRS ${_GLIB_CONFIG_DIR})
    find_library(GLIB2_LIBRARIES glib-2.0
        HINTS ${_WS_LIBS_DIRS}
        PATH_SUFFIXES vcpkg-export/x64-windows/lib lib
        REQUIRED)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLIB2 REQUIRED glib-2.0)
endif()

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
    $<$<C_COMPILER_ID:GNU,Clang>:-Wall -Wextra -std=c11>
    $<$<C_COMPILER_ID:MSVC>:/W3>
)

target_link_libraries(packet-zenoh PRIVATE
    ${Wireshark_LIBRARIES}
    ${GLIB2_LIBRARIES}
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
