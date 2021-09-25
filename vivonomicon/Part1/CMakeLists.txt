cmake_minimum_required(VERSION 3.21.3)

project(cmakeTrial)

enable_language(C ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set( ASM_SOURCE
    core.S
    )

add_executable(${PROJECT_NAME} ${ASM_SOURCE})

target_compile_options(${PROJECT_NAME} PRIVATE
        -mcpu=cortex-m4
        -mthumb
        -Wall
		-Werror
        $<$<CONFIG:Debug>:-Og>
        )

target_link_options(${PROJECT_NAME} PRIVATE
        -T${CMAKE_SOURCE_DIR}/STM32F303VCT6.ld
        -mcpu=cortex-m4
        -mthumb
        -specs=nosys.specs
        -lgcc
        -nostdlib
        )

# Print executable size
add_custom_command(TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND arm-none-eabi-size ${PROJECT_NAME})

# Create hex file
add_custom_command(TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND arm-none-eabi-objcopy -O ihex ${PROJECT_NAME} ${PROJECT_NAME}.hex
        COMMAND arm-none-eabi-objcopy -O binary ${PROJECT_NAME} ${PROJECT_NAME}.bin)
