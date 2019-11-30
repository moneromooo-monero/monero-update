#  monero-update - An downloaded/checker updater for Monero
#
#  Copyright (c) 2019, The Monero Project
#
#  All rights reserved.
#  
#  monero-update is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  monero-update is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with monero-update.  If not, see <https://www.gnu.org/licenses/>.

# Qt5 requires at least CMake version 3.1.0
cmake_minimum_required(VERSION 3.1.0)

project(monero-update VERSION 0.1 LANGUAGES C CXX)

# PkgConfig is used to find gpgme and set up its link line properly in MSYS2.
# Some Linux distros do not provide a .pc file for gpgme, so we will use the
# provided cmake/FindGPGME.cmake cmake module for that.
find_package(PkgConfig)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_SOURCE_DIR}/cmake")

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(monero_update_sources
  src/main.cpp
  src/updater.cpp

  src/common/dns_utils.cpp
  src/common/download.cpp
  src/common/threadpool.cpp
  src/common/sha256sum.cpp
  src/common/updates.cpp
  src/common/vercmp.cpp

  src/epee/src/hex.cpp
  src/epee/src/http_auth.cpp
  src/epee/src/memwipe.c
  src/epee/src/mlocker.cpp
  src/epee/src/mlog.cpp
  src/epee/src/net_helper.cpp
  src/epee/src/net_ssl.cpp
  src/epee/src/net_utils_base.cpp
  src/epee/src/string_tools.cpp
  src/epee/src/wipeable_string.cpp

  src/easylogging++/easylogging++.cc

  monero-update.qrc
)
set(monero_update_headers
)

include_directories(src/epee/include)
include_directories(src/easylogging++)
include_directories(src)

# Check whether we're on a 32-bit or 64-bit system
if(CMAKE_SIZEOF_VOID_P EQUAL "8")
  set(DEFAULT_BUILD_64 ON)
else()
  set(DEFAULT_BUILD_64 OFF)
endif()
option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})

if(BUILD_64)
  set(ARCH_WIDTH "64")
else()
  set(ARCH_WIDTH "32")
endif()
message(STATUS "Building for a ${ARCH_WIDTH}-bit system")

if(MINGW)
  string(REGEX MATCH "^[^/]:/[^/]*" msys2_install_path "${CMAKE_C_COMPILER}")
  message(STATUS "MSYS location: ${msys2_install_path}")
  set(CMAKE_INCLUDE_PATH "${msys2_install_path}/mingw${ARCH_WIDTH}/include")
  # This is necessary because otherwise CMake will make Boost libraries -lfoo
  # rather than a full path. Unfortunately, this makes the shared libraries get
  # linked due to a bug in CMake which misses putting -static flags around the
  # -lfoo arguments.
  set(DEFLIB ${msys2_install_path}/mingw${ARCH_WIDTH}/lib)
  list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
  list(REMOVE_ITEM CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
endif()

# Qt5 components that we use are required, otherwise what are we doing ?
if(MINGW AND STATIC)
  # Find Qt5 cmake config folder of the MSYS2 mingw-w64-{x86_64,i686}-qt5-static package(s)
  find_package(Qt5 REQUIRED COMPONENTS Core Gui Network Quick Qml Widgets CONFIG NO_DEFAULT_PATH PATHS ${msys2_install_path}/mingw${ARCH_WIDTH}/qt5-static/lib/cmake)
else()
  find_package(Qt5 REQUIRED COMPONENTS Core Gui Network Quick Qml Widgets)
endif()
message(STATUS "Using Qt5 package/config found at ${Qt5_DIR}")

if (NOT DEFINED ENV{DEVELOPER_LOCAL_TOOLS})
  message(STATUS "Could not find DEVELOPER_LOCAL_TOOLS in env (not required)")
  set(BOOST_IGNORE_SYSTEM_PATHS_DEFAULT OFF)
elseif ("$ENV{DEVELOPER_LOCAL_TOOLS}" EQUAL 1)
  message(STATUS "Found: env DEVELOPER_LOCAL_TOOLS = 1")
  set(BOOST_IGNORE_SYSTEM_PATHS_DEFAULT ON)
else()
  message(STATUS "Found: env DEVELOPER_LOCAL_TOOLS = 0")
  set(BOOST_IGNORE_SYSTEM_PATHS_DEFAULT OFF)
endif()

message(STATUS "BOOST_IGNORE_SYSTEM_PATHS defaults to ${BOOST_IGNORE_SYSTEM_PATHS_DEFAULT}")
option(BOOST_IGNORE_SYSTEM_PATHS "Ignore boost system paths for local boost installation" ${BOOST_IGNORE_SYSTEM_PATHS_DEFAULT})

if (${BOOST_IGNORE_SYSTEM_PATHS} STREQUAL "ON")
  set(Boost_NO_SYSTEM_PATHS TRUE)
endif()

set(OLD_LIB_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(Boost_NO_BOOST_CMAKE ON)
if(STATIC)
  set(OPENSSL_USE_STATIC_LIBS ON)
  if(MINGW)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif()

  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif()
find_package(Boost 1.58 QUIET REQUIRED COMPONENTS system filesystem thread chrono regex)

set(CMAKE_FIND_LIBRARY_SUFFIXES ${OLD_LIB_SUFFIXES})
if(NOT Boost_FOUND)
  die("Could not find Boost libraries, please make sure you have installed Boost or libboost-all-dev (>=1.58) or the equivalent")
elseif(Boost_FOUND)
  message(STATUS "Found Boost Version: ${Boost_VERSION}")
  if (Boost_VERSION VERSION_LESS 10 AND Boost_VERSION VERSION_LESS 1.62.0 AND NOT (OPENSSL_VERSION VERSION_LESS 1.1))
    set(BOOST_BEFORE_1_62 true)
  endif()
  if (NOT Boost_VERSION VERSION_LESS 10 AND Boost_VERSION VERSION_LESS 106200 AND NOT (OPENSSL_VERSION VERSION_LESS 1.1))
    set(BOOST_BEFORE_1_62 true)
  endif()
  if (BOOST_BEFORE_1_62)
      message(FATAL_ERROR "Boost ${Boost_VERSION} (older than 1.62) is too old to link with OpenSSL ${OPENSSL_VERSION} (1.1 or newer) found at ${OPENSSL_INCLUDE_DIR} and ${OPENSSL_LIBRARIES}. "
                          "Update Boost or install OpenSSL 1.0 and set path to it when running cmake: "
                          "cmake -DOPENSSL_ROOT_DIR='/usr/include/openssl-1.0'")
  endif()
endif()

include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

# Handle OpenSSL, used for sha256sum on binary updates and light wallet ssl http
if (CMAKE_SYSTEM_NAME MATCHES "(SunOS|Solaris)")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthreads")
endif ()

if (APPLE AND NOT IOS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=x86-64 -fvisibility=default -std=c++11")
  if (NOT OpenSSL_DIR)
      EXECUTE_PROCESS(COMMAND brew --prefix openssl
        OUTPUT_VARIABLE OPENSSL_ROOT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using OpenSSL found at ${OPENSSL_ROOT_DIR}")
  endif()
endif()

find_package(OpenSSL REQUIRED)
message(STATUS "Using OpenSSL include dir at ${OPENSSL_INCLUDE_DIR}")
include_directories(${OPENSSL_INCLUDE_DIR})
if(STATIC AND NOT IOS)
  if(UNIX)
    set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARIES};${CMAKE_DL_LIBS};${CMAKE_THREAD_LIBS_INIT}")
  endif()
endif()

find_package(Unbound)
if (NOT DEFINED ENV{DEVELOPER_LIBUNBOUND_OLD})
  message(STATUS "Could not find DEVELOPER_LIBUNBOUND_OLD in env (not required)")
elseif ("$ENV{DEVELOPER_LIBUNBOUND_OLD}" EQUAL 1)
  message(STATUS "Found: env DEVELOPER_LIBUNBOUND_OLD = 1, will use the work around")
  add_definitions(-DDEVELOPER_LIBUNBOUND_OLD)
elseif ("$ENV{DEVELOPER_LIBUNBOUND_OLD}" EQUAL 0)
  message(STATUS "Found: env DEVELOPER_LIBUNBOUND_OLD = 0")
else()
  message(STATUS "Found: env DEVELOPER_LIBUNBOUND_OLD with bad value. Will NOT use the work around")
endif()

if(NOT UNBOUND_INCLUDE_DIR OR STATIC)
  # NOTE: If STATIC is true, CMAKE_FIND_LIBRARY_SUFFIXES has been reordered.
  # unbound has config tests which used OpenSSL libraries, so -ldl may need to
  # be set in this case.
  # The unbound CMakeLists.txt can set it, since it's also needed for the
  # static OpenSSL libraries set up there after with target_link_libraries.
  add_subdirectory(external/unbound)

  set(UNBOUND_STATIC true)
  set(UNBOUND_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/external/unbound/libunbound")
  set(UNBOUND_LIBRARY "unbound")
  set(UNBOUND_LIBRARY_DIRS "${LIBEVENT2_LIBDIR}")
else()
  message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIR}")
  if(UNBOUND_LIBRARIES)
    message(STATUS "Found libunbound shared library")
    set(UNBOUND_STATIC false)
    set(UNBOUND_INCLUDE ${UNBOUND_INCLUDE_DIR})
    set(UNBOUND_LIBRARY ${UNBOUND_LIBRARIES})
    set(UNBOUND_LIBRARY_DIRS "")
  else()
    die("Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
  endif()
endif()

if(MINGW)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wa,-mbig-obj")
  set(EXTRA_LIBRARIES mswsock;ws2_32;iphlpapi;crypt32;bcrypt)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
  if(DEPENDS)
    set(ICU_LIBRARIES icuio icui18n icuuc icudata icutu iconv)
  else()
    set(ICU_LIBRARIES icuio icuin icuuc icudt icutu iconv)
  endif()
elseif(APPLE OR OPENBSD OR ANDROID)
  set(EXTRA_LIBRARIES "")
elseif(FREEBSD)
  set(EXTRA_LIBRARIES execinfo)
elseif(DRAGONFLY)
  find_library(COMPAT compat)
  set(EXTRA_LIBRARIES execinfo ${COMPAT})
elseif(CMAKE_SYSTEM_NAME MATCHES "(SunOS|Solaris)")
  set(EXTRA_LIBRARIES socket nsl resolv)
elseif(NOT MSVC AND NOT DEPENDS)
  find_library(RT rt)
  set(EXTRA_LIBRARIES ${RT})
endif()
find_library(Z z)
if(Z)
  list(APPEND EXTRA_LIBRARIES ${Z})
endif()

list(APPEND EXTRA_LIBRARIES ${CMAKE_DL_LIBS})

if(STATIC)
  # STATIC already configures most deps to be linked in statically,
  # here we make more deps static if the platform permits it
  set(Qt5_USE_STATIC_LIBS ON)
  set(Qt5_USE_STATIC_RUNTIME ON)
  # The definitions below are commented out because it seems (most?) Linux distros
  # do not provide static Qt5 libs, so the binary will be linked against shared Qt5 libs.
  # Uncomment if you have static Qt5 libs and you know what you are doing (see the MINGW
  # section below).
  # add_definitions(-DUSE_STATIC_QT -DQT_STATICPLUGIN)
  if (MINGW)
    # On Windows, this is as close to fully-static as we get:
    # this leaves only deps on /c/Windows/system32/*.dll
    set(STATIC_FLAGS "-static")
    add_definitions(-DQT_STATIC -DQT_STATICPLUGIN)
    # Here we set the path to static Qt5 QML libs provided by mingw-w64-{x86_64,i686}-qt5-static MSYS2 package(s).
    set(MSYS2_QML_STATIC_PATH "${Qt5_DIR}/../../../share/qt5/qml")
    # Here we set link paths manually to static Qt5 QML libs specified below in QT5_STATICLIBS because pkgconfig
    # or cmake config files are not provided in MSYS2 with these libs.
    link_directories(${MSYS2_QML_STATIC_PATH}/QtQuick.2 ${MSYS2_QML_STATIC_PATH}/QtQuick/Controls ${MSYS2_QML_STATIC_PATH}/QtQuick/Controls/Styles/Flat ${MSYS2_QML_STATIC_PATH}/QtQuick/Layouts ${MSYS2_QML_STATIC_PATH}/QtQuick/Window.2 ${MSYS2_QML_STATIC_PATH}/QtGraphicalEffects ${MSYS2_QML_STATIC_PATH}/QtGraphicalEffects/private)
    set(QT5_STATICLIBS qtquick2plugin qtquickcontrolsplugin qtquickextrasflatplugin qquicklayoutsplugin windowplugin qtgraphicaleffectsplugin qtgraphicaleffectsprivate Qt5::QWindowsIntegrationPlugin)
  elseif (NOT (APPLE OR FREEBSD OR OPENBSD OR DRAGONFLY))
    # On Linux, we don't support fully static build, but these can be static
    set(STATIC_FLAGS "${STATIC_FLAGS} -static-libgcc -static-libstdc++")
  endif()
  set(CMAKE_AUTOSTATICPLUGINS ON)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${STATIC_FLAGS}")
endif()

# Use PkgConf module in MSYS2 and cmake module elsewhere to find gpgme.
# Using the provided cmake/FindGPGME.cmake module in MSYS2 does not set separate vars for static and dynamic libs,
# making our lives miserable crafting the link line with static gpgme dependencies when building static.
if(MINGW)
  pkg_check_modules(GPGME REQUIRED gpgme)
  if(NOT GPGME_LIBRARIES OR NOT GPGME_STATIC_LIBRARIES)
    message(FATAL_ERROR "gpgme library not found")
  endif()
else()
  find_package(GPGME REQUIRED)
  if(NOT GPGME_VANILLA_LIBRARIES)
    message(FATAL_ERROR "Vanilla gpgme library not found")
  endif()
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -W -Wno-unused-parameter -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -W -Wno-unused-parameter -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DAUTO_INITIALIZE_EASYLOGGINGPP")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

# Final setup for libunbound
include_directories(${UNBOUND_INCLUDE})
link_directories(${UNBOUND_LIBRARY_DIRS})

# Final setup for gpgme
# gpgme vars for includes and libs are called differently between PkgConf and FindGPGME.cmake
link_directories(${GPGME_LIBRARY_DIRS})
if(MINGW)
  include_directories(${GPGME_INCLUDE_DIRS})
  if(STATIC)
    set(GPGME_LIBS ${GPGME_STATIC_LIBRARIES})
  else()
    set(GPGME_LIBS ${GPGME_LIBRARIES})
  endif()
else()
  include_directories(${GPGME_INCLUDES})
  set(GPGME_LIBS ${GPGME_VANILLA_LIBRARIES})
endif()

# Set some Win32 Specific settings
if(WIN32)
set(GUI_TYPE WIN32)
endif(WIN32)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_FLAG} ${WARNINGS} ${C_WARNINGS} ${COVERAGE_FLAGS} ${PIC_FLAG} ${C_SECURITY_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_CPP_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${COVERAGE_FLAGS} ${PIC_FLAG} ${CXX_SECURITY_FLAGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")

add_executable(monero-update
  ${GUI_TYPE}
  ${monero_update_sources}
)

target_link_libraries(monero-update
  Qt5::Core
  Qt5::Gui
  Qt5::Qml
  Qt5::Quick
  Qt5::Network
  Qt5::Widgets
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_REGEX_LIBRARY}
  ${Boost_THREAD_LIBRARY}
  ${Boost_CHRONO_LIBRARY}
  ${Boost_SYSTEM_LIBRARY}
  ${GPGME_LIBS}
  ${UNBOUND_LIBRARY}
  ${OPENSSL_LIBRARIES}
  ${QT5_STATICLIBS}
  ${EXTRA_LIBRARIES}
)
