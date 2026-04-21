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
    # Headers from the downloaded source tarball (build-wireshark-windows.ps1 step 2)
    file(GLOB _WS_SRC_DIRS "C:/wsbuild/wireshark-*")
    list(FILTER _WS_SRC_DIRS EXCLUDE REGEX "libs")
    find_path(Wireshark_INCLUDE_DIRS wireshark.h
        HINTS ${_WS_SRC_DIRS}
        REQUIRED)
    # Import libraries from the choco-installed Wireshark application
    find_library(Wireshark_LIBRARIES wireshark
        HINTS
            "C:/Program Files/Wireshark"
            "C:/Program Files (x86)/Wireshark"
        REQUIRED)
else()
    find_path(Wireshark_INCLUDE_DIRS wireshark.h
        PATH_SUFFIXES wireshark
        REQUIRED)
    find_library(Wireshark_LIBRARIES wireshark REQUIRED)
    find_library(Wireshark_WSUTIL_LIB wsutil)  # pulled transitively on Linux; needed explicitly on macOS
endif()
message(STATUS "Wireshark: include=${Wireshark_INCLUDE_DIRS} lib=${Wireshark_LIBRARIES}")

# GLib is a Wireshark dependency not always transitively exposed.
# On Windows glib ships inside Wireshark's win64-libs bundle; on Linux/macOS
# pkg-config finds it from the system package.
if(WIN32)
    # GLib headers live inside the Wireshark source tree (glib.h is re-exported
    # from epan/glib-compat.h and the source tree ships glib headers for plugins).
    # The import library is bundled with the installed Wireshark application.
    set(_WS_INSTALL "C:/Program Files/Wireshark")
    find_path(GLIB2_INCLUDE_DIRS glib.h
        HINTS
            "${Wireshark_INCLUDE_DIRS}/include"
            "${_WS_INSTALL}/include"
        PATH_SUFFIXES glib-2.0
        # Not REQUIRED — Wireshark headers may already pull glib.h in transitively
    )
    find_library(GLIB2_LIBRARIES glib-2.0
        HINTS "${_WS_INSTALL}"
        # Not REQUIRED — glib symbols may be resolved transitively via wireshark.lib
    )
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLIB2 REQUIRED IMPORTED_TARGET glib-2.0)
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

if(WIN32)
    target_link_libraries(packet-zenoh PRIVATE
        ${Wireshark_LIBRARIES}
        $<$<BOOL:${GLIB2_LIBRARIES}>:${GLIB2_LIBRARIES}>
        ${ZENOH_CODEC_FFI_LIB}
    )
else()
    target_link_libraries(packet-zenoh PRIVATE
        ${Wireshark_LIBRARIES}
        $<$<BOOL:${Wireshark_WSUTIL_LIB}>:${Wireshark_WSUTIL_LIB}>
        PkgConfig::GLIB2
        ${ZENOH_CODEC_FFI_LIB}
    )
endif()

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
