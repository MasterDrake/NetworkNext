foreach(example IN ITEMS simple_client simple_server upgraded_client upgraded_server complex_client complex_server)
    create_example_target(${example})
endforeach()