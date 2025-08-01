# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

set(SHM_INCLUDE_DIR /home/emma/mvfst/shm/shm/include)
set(SHM_LIBRARIES /home/emma/mvfst/shm/shm/lib)

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

add_executable(opvshm opvshm/main.cpp)

target_include_directories(
  opvshm 
  PRIVATE
  ${SHM_INCLUDE_DIR}
)

target_link_directories(
  opvshm 
  PRIVATE
  ${SHM_LIBRARIES}
)

target_compile_options(
  opvshm
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  opvshm PUBLIC
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  shm
)

add_executable(opv_client opvshm/Usr_cli.c) 

target_include_directories(
  opv_client
  PRIVATE
  ${SHM_INCLUDE_DIR}
)

target_link_directories(
  opv_client
  PRIVATE
  ${SHM_LIBRARIES}
)

target_compile_options(
  opv_client
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  opv_client PUBLIC
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  shm
)

add_executable(opv_server opvshm/App_srv.c) 

target_include_directories(
  opv_server
  PRIVATE
  ${SHM_INCLUDE_DIR}
)

target_link_directories(
  opv_server
  PRIVATE
  ${SHM_LIBRARIES}
)

target_compile_options(
  opv_server
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  opv_server PUBLIC
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  shm
)