cmake_minimum_required(VERSION 3.15)
project(AntiDDoS VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    find_package(WinPcap QUIET)
    if(WinPcap_FOUND)
        include_directories(${WINPCAP_INCLUDE_DIR})
    endif()
elseif(UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBPCAP REQUIRED libpcap)
    include_directories(${LIBPCAP_INCLUDE_DIRS})
endif()

set(CORE_SOURCES
    packet-engine/src/packet_engine.cpp
    packet-engine/src/vpn_detector.cpp
    rate-limiting/src/rate_limiter.cpp
    advanced-mitigation/src/behavioral_analyzer.cpp
    advanced-mitigation/src/geo_blocker.cpp
    game-protection/src/game_protector.cpp
    asn-database/src/asn_database.cpp
    attack-correlator/src/attack_correlator.cpp
    shared/src/utils.cpp
    shared/src/logger.cpp
    shared/src/platform.cpp
)

set(EXTENDED_SOURCES
    ml-detection/src/ml_detector.cpp
    honeypot/src/honeypot.cpp
    auto-response/src/auto_responder.cpp
    api-dashboard/src/api_gateway.cpp
    distributed/src/cluster_manager.cpp
    threat-intel/src/threat_intel.cpp
)

add_library(antiddos_core STATIC ${CORE_SOURCES})
add_library(antiddos_extended STATIC ${EXTENDED_SOURCES})

target_include_directories(antiddos_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/packet-engine/include
    ${CMAKE_CURRENT_SOURCE_DIR}/rate-limiting/include
    ${CMAKE_CURRENT_SOURCE_DIR}/advanced-mitigation/include
    ${CMAKE_CURRENT_SOURCE_DIR}/game-protection/include
    ${CMAKE_CURRENT_SOURCE_DIR}/asn-database/include
    ${CMAKE_CURRENT_SOURCE_DIR}/attack-correlator/include
    ${CMAKE_CURRENT_SOURCE_DIR}/orchestration/include
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include
    ${CMAKE_CURRENT_SOURCE_DIR}/config
)

target_include_directories(antiddos_extended PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/ml-detection/include
    ${CMAKE_CURRENT_SOURCE_DIR}/honeypot/include
    ${CMAKE_CURRENT_SOURCE_DIR}/auto-response/include
    ${CMAKE_CURRENT_SOURCE_DIR}/api-dashboard/include
    ${CMAKE_CURRENT_SOURCE_DIR}/distributed/include
    ${CMAKE_CURRENT_SOURCE_DIR}/threat-intel/include
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/include
)

if(WIN32)
    target_link_libraries(antiddos_core ws2_32 iphlpapi)
    target_link_libraries(antiddos_extended antiddos_core)
elseif(UNIX)
    target_link_libraries(antiddos_core ${LIBPCAP_LIBRARIES} pthread)
    target_link_libraries(antiddos_extended antiddos_core pthread)
endif()

add_executable(antiddos-cli orchestration/src/main_cli.cpp orchestration/src/cli.cpp)
target_link_libraries(antiddos-cli antiddos_core antiddos_extended)

add_executable(antiddos-daemon orchestration/src/daemon.cpp)
target_link_libraries(antiddos-daemon antiddos_core antiddos_extended)

add_executable(antiddos-api api-dashboard/src/api_main.cpp)
target_link_libraries(antiddos-api antiddos_core antiddos_extended)

add_executable(antiddos-cluster distributed/src/cluster_main.cpp)
target_link_libraries(antiddos-cluster antiddos_core antiddos_extended)

add_executable(antiddos-intel threat-intel/src/intel_main.cpp)
target_link_libraries(antiddos-intel antiddos_core antiddos_extended)

if(UNIX)
    set(XDP_SOURCES
        ebpf-xdp/src/xdp_loader.cpp
        ebpf-xdp/src/xdp_cli.cpp
    )
    
    add_library(antiddos_xdp STATIC ${XDP_SOURCES})
    target_include_directories(antiddos_xdp PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ebpf-xdp/include
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/include
    )
    target_link_libraries(antiddos_xdp bpf elf z)
    
    add_executable(xdp-cli ebpf-xdp/src/xdp_main.cpp)
    target_link_libraries(xdp-cli antiddos_xdp antiddos_core)
    
    add_executable(xdp-loader ebpf-xdp/src/xdp_loader_main.cpp)
    target_link_libraries(xdp-loader antiddos_xdp)
endif()

if(WIN32)
    install(TARGETS antiddos-cli antiddos-daemon antiddos-api antiddos-cluster antiddos-intel DESTINATION bin)
    install(DIRECTORY config/ DESTINATION etc/antiddos)
else()
    install(TARGETS antiddos-cli antiddos-daemon antiddos-api antiddos-cluster antiddos-intel xdp-cli xdp-loader DESTINATION /usr/local/bin)
    install(DIRECTORY config/ DESTINATION /etc/antiddos)
    install(DIRECTORY ebpf-xdp/src/ DESTINATION /usr/lib/antiddos FILES_MATCHING PATTERN "*.o")
endif()

enable_testing()
add_subdirectory(tests)