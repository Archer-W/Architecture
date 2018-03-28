################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/Simulation/simulation_test.cpp 

O_SRCS += \
../src/Simulation/simulation_test.o 

OBJS += \
./src/Simulation/simulation_test.o 

CPP_DEPS += \
./src/Simulation/simulation_test.d 


# Each subdirectory must supply rules for building sources it contributes
src/Simulation/%.o: ../src/Simulation/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -std=c++0x -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


