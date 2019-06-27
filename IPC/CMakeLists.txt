cmake_minimum_required(VERSION 3.0)
project (IPC_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(Broker ${CMAKE_CURRENT_SOURCE_DIR}/broker.cpp)
target_compile_options(Broker PRIVATE -std=c++17 -Wall -Werror -O2)
target_include_directories( Broker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ )

add_executable(Receiver ${CMAKE_CURRENT_SOURCE_DIR}/receiver.cpp)
target_compile_options(Receiver PRIVATE -std=c++17 -Wall -Werror -O2)
target_include_directories( Receiver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ )

add_executable(Sender ${CMAKE_CURRENT_SOURCE_DIR}/sender.cpp)
target_compile_options(Sender PRIVATE -std=c++17 -Wall -Werror -O2)
target_include_directories( Sender PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ )

add_executable(Both ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
target_compile_options(Both PRIVATE -std=c++17 -Wall -Werror -O2)
target_include_directories( Both PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ )

target_link_libraries(Broker
                    qpid-proton-cpp
                    pthread
                    PocoFoundation
                    )
target_link_libraries(Sender
                    qpid-proton-cpp
                    pthread
                    PocoFoundation
                    )
target_link_libraries(Receiver
                    qpid-proton-cpp
                    pthread
                    PocoFoundation
                    )
target_link_libraries(Both
                    qpid-proton-cpp
                    pthread
                    PocoFoundation
                    )
