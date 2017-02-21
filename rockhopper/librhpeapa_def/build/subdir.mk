################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../rhp_eap_auth_main_auth.c \
../rhp_eap_auth_radius.c \
../rhp_eap_auth_syspxy_auth.c \
../rhp_eap_auth_syspxy_xauth.c 

OBJS += \
./rhp_eap_auth_main_auth.o \
./rhp_eap_auth_radius.o \
./rhp_eap_auth_syspxy_auth.o \
./rhp_eap_auth_syspxy_xauth.o 

C_DEPS += \
./rhp_eap_auth_main_auth.d \
./rhp_eap_auth_radius.d \
./rhp_eap_auth_syspxy_auth.d \
./rhp_eap_auth_syspxy_xauth.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -D_GNU_SOURCE -D_REENTRANT -D_FORTIFY_SOURCE=1 -DRHP_TYPES_DONT_DEF -DRHP_MUTEX_DEBUG -DRHP_REFCNT_DEBUG -DRHP_LIBXML2 -I/usr/include/libxml2 -I../../include -O3 -g3 -Wall -c -fmessage-length=0 -fno-strict-aliasing -fstack-protector -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


