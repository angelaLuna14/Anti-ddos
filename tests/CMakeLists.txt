enable_testing()

add_executable(antiddos_tests test_main.cpp)

target_link_libraries(antiddos_tests antiddos_core antiddos_extended)

add_test(NAME AntiDDoSTests COMMAND antiddos_tests)