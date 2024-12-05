add_library(next STATIC)
add_library(NetworkNext::next ALIAS next)

target_sources(next PRIVATE
							next.cpp
							next_address.cpp
							next_autodetect.cpp
							next_base64.cpp
							next_client.cpp
							next_config.cpp
							next_crypto.cpp
							next_hash.cpp
							next_packets.cpp
							next_packet_filter.cpp
							next_platform_gdk.cpp
							next_platform_linux.cpp
							next_platform_mac.cpp
							next_platform_ps4.cpp
							next_platform_ps5.cpp
							next_platform_switch.cpp
							next_platform_windows.cpp
							next_route_manager.cpp
							next_server.cpp
							next_tests.cpp)

target_sources(next PUBLIC 
							../include/networknext/next.h
							../include/networknext/next_address.h
							../include/networknext/next_autodetect.h
							../include/networknext/next_bandwidth_limiter.h
							../include/networknext/next_base64.h
							../include/networknext/next_bitpacker.h
							../include/networknext/next_client.h
							../include/networknext/next_config.h
							../include/networknext/next_constants.h
							../include/networknext/next_continue_token.h
							../include/networknext/next_crypto.h
							../include/networknext/next_hash.h
							../include/networknext/next_header.h
							../include/networknext/next_internal_config.h
							../include/networknext/next_jitter_tracker.h
							../include/networknext/next_memory_checks.h
							../include/networknext/next_out_of_order_tracker.h
							../include/networknext/next_packets.h
							../include/networknext/next_packet_filter.h
							../include/networknext/next_packet_loss_tracker.h
							../include/networknext/next_pending_session_manager.h
							../include/networknext/next_ping_history.h
							../include/networknext/next_platform.h
							../include/networknext/next_platform_gdk.h
							../include/networknext/next_platform_linux.h
							../include/networknext/next_platform_mac.h
							../include/networknext/next_platform_ps4.h
							../include/networknext/next_platform_ps5.h
							../include/networknext/next_platform_switch.h
							../include/networknext/next_platform_windows.h
							../include/networknext/next_proxy_session_manager.h
							../include/networknext/next_queue.h
							../include/networknext/next_read_write.h
							../include/networknext/next_relay_manager.h
							../include/networknext/next_replay_protection.h
							../include/networknext/next_route_manager.h
							../include/networknext/next_route_token.h
							../include/networknext/next_serialize.h
							../include/networknext/next_server.h
							../include/networknext/next_session_manager.h
							../include/networknext/next_stream.h
							../include/networknext/next_tests.h
							../include/networknext/next_upgrade_token.h
							../include/networknext/next_util.h)

target_include_directories(next PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(next PRIVATE sodium)
target_include_directories(next PUBLIC include)

target_compile_definitions(next PRIVATE NEXT_DEVELOPMENT)

target_compile_definitions(next PRIVATE
    $<$<CONFIG:Debug>:NEXT_ENABLE_MEMORY_CHECKS=1>
    $<$<CONFIG:Debug>:NEXT_ASSERTS=1>
)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(next PRIVATE -Wno-sign-compare)
endif()
