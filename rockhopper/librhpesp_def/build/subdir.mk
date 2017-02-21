################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../rhp_esp_impl.c 

OBJS += \
./rhp_esp_impl.o 

C_DEPS += \
./rhp_esp_impl.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -D_GNU_SOURCE -D_REENTRANT -D_FORTIFY_SOURCE=1 -DRHP_MUTEX_DEBUG -DRHP_REFCNT_DEBUG -DRHP_LIBXML2 -I/usr/include/libxml2 -I../../include -O3 -g3 -Wall -c -fmessage-length=0 -fno-strict-aliasing -fstack-protector -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


