#  monero-update - An downloaded/checker updater for Monero
#
#  Copyright (c) 2019, The Monero Project
#
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without modification, are
#  permitted provided that the following conditions are met:
#  
#  1. Redistributions of source code must retain the above copyright notice, this list of
#     conditions and the following disclaimer.
#  
#  2. Redistributions in binary form must reproduce the above copyright notice, this list
#     of conditions and the following disclaimer in the documentation and/or other
#     materials provided with the distribution.
#  
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#     used to endorse or promote products derived from this software without specific
#     prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
#  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
#  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
#  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.0.0)

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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_FLAG} ${WARNINGS} ${C_WARNINGS} ${COVERAGE_FLAGS} ${PIC_FLAG} ${C_SECURITY_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_CPP_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${COVERAGE_FLAGS} ${PIC_FLAG} ${CXX_SECURITY_FLAGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")

find_package(Qt5Qml REQUIRED)
find_package(Qt5Quick REQUIRED)

include_directories(src/epee/include)
include_directories(src/easylogging++)
include_directories(src)

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
  if(MINGW)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif()

  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif()
find_package(Boost 1.58 QUIET REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options locale)

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
  add_subdirectory(unbound)

  set(UNBOUND_STATIC true PARENT_SCOPE)
  set(UNBOUND_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/unbound/libunbound" PARENT_SCOPE)
  set(UNBOUND_LIBRARY "unbound" PARENT_SCOPE)
  set(UNBOUND_LIBRARY_DIRS "${LIBEVENT2_LIBDIR}" PARENT_SCOPE)
else()
  message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIR}")
  if(UNBOUND_LIBRARIES)
    message(STATUS "Found libunbound shared library")
    set(UNBOUND_STATIC false PARENT_SCOPE)
    set(UNBOUND_INCLUDE ${UNBOUND_INCLUDE_DIR} PARENT_SCOPE)
    set(UNBOUND_LIBRARY ${UNBOUND_LIBRARIES} PARENT_SCOPE)
    set(UNBOUND_LIBRARY_DIRS "" PARENT_SCOPE)
  else()
    die("Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
  endif()
endif()

if(MINGW)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wa,-mbig-obj")
  set(EXTRA_LIBRARIES mswsock;ws2_32;iphlpapi;crypt32;bcrypt)
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

list(APPEND EXTRA_LIBRARIES ${CMAKE_DL_LIBS})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -W -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -W -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DAUTO_INITIALIZE_EASYLOGGINGPP")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

# Final setup for libunbound
include_directories(${UNBOUND_INCLUDE})
link_directories(${UNBOUND_LIBRARY_DIRS})

add_executable(monero-update
  ${monero_update_sources}
)

target_link_libraries(monero-update
  unbound
  boost_filesystem
  boost_regex
  boost_thread
  boost_chrono
  boost_system
  ${UNBOUND_LIBRARY}
  ${OPENSSL_LIBRARIES}
)

qt5_use_modules(monero-update Qml Quick)

