# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

set(SHM_INCLUDE_DIR /home/emma/shm/shm/include)
set(SHM_LIBRARIES /home/emma/shm/shm/lib)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/unix_shm/${header_dir})
endforeach()

add_executable(uixshm opvshm/main.cpp)

target_include_directories(
  uixshm 
  PRIVATE
  ${SHM_INCLUDE_DIR}
)

target_link_directories(
  uixshm 
  PRIVATE
  ${SHM_LIBRARIES}
)

target_compile_options(
  uixshm
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  uixshm PUBLIC
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  shm
)

add_executable(uix_client opvshm/Usr_cli.c) 

target_include_directories(
  uix_client
  PRIVATE
  ${SHM_INCLUDE_DIR}
)

target_link_directories(
  uix_client
  PRIVATE
  ${SHM_LIBRARIES}
)

target_compile_options(
  uix_client
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  uix_client PUBLIC
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  shm
  ev
)

add_executable(uix_server opvshm/App_srv.c) 

target_include_directories(
  uix_server
  PRIVATE
  ${SHM_INCLUDE_DIR}
)

target_link_directories(
  uix_server
  PRIVATE
  ${SHM_LIBRARIES}
)

target_compile_options(
  uix_server
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  uix_server PUBLIC
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  shm
  ev
)