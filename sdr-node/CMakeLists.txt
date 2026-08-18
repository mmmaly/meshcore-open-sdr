cmake_minimum_required(VERSION 3.14)
project(meshcore-sdr-node VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# meshcore-cpp-decoder provides packet decode/encode and all crypto.
# Default expects a sibling checkout; override with -DDECODER_DIR=...
set(DECODER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../meshcore-cpp-decoder"
    CACHE PATH "Path to a meshcore-cpp-decoder checkout")

if(NOT EXISTS "${DECODER_DIR}/CMakeLists.txt")
  message(FATAL_ERROR "meshcore-cpp-decoder not found at ${DECODER_DIR}. "
          "Clone https://github.com/mmmaly/meshcore-cpp-decoder next to this "
          "repo or pass -DDECODER_DIR=<path>.")
endif()

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(${DECODER_DIR} meshcore-decoder-build)

add_executable(meshcore-sdr-node
  src/main.cpp
  src/node.cpp
  src/node_config.cpp
  src/radio_sdr.cpp
  src/companion_server.cpp
)
target_link_libraries(meshcore-sdr-node PRIVATE meshcore_decoder pthread)

add_executable(make_test_packets tests/make_test_packets.cpp)
target_link_libraries(make_test_packets PRIVATE meshcore_decoder)

enable_testing()
add_test(NAME protocol
         COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/protocol_test.py
                 $<TARGET_FILE:meshcore-sdr-node> $<TARGET_FILE:make_test_packets>
                 $<TARGET_FILE:meshcore-decoder>)
