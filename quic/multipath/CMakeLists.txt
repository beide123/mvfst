# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

set(SHM_INCLUDE_DIR ../../shm/shm/include)
set(SHM_LIBRARIES ../../shm/shm/lib)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/multipath/${header_dir})
endforeach()

add_executable(mdlw mdlw/main.cpp)

target_include_directories(
  mdlw 
  PRIVATE
  ${SHM_INCLUDE_DIR}
)

target_link_directories(
  mdlw 
  PRIVATE
  ${SHM_LIBRARIES}
)

target_compile_options(
  mdlw
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mdlw PUBLIC
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  shm
)
