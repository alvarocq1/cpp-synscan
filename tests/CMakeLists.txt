# Each test file compiles to its own executable so failures are isolated.

add_executable(test_port_spec test_port_spec.cpp)
target_link_libraries(test_port_spec PRIVATE synscan_lib)
add_test(NAME port_spec COMMAND test_port_spec)

add_executable(test_args test_args.cpp)
target_link_libraries(test_args PRIVATE synscan_lib)
add_test(NAME args COMMAND test_args)

add_executable(test_output test_output.cpp)
target_link_libraries(test_output PRIVATE synscan_lib)
add_test(NAME output COMMAND test_output)
