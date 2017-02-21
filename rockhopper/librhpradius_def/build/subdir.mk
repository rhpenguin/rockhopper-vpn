################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../rhp_radius_attr.c \
../rhp_radius_attr_basic.c \
../rhp_radius_attr_eap.c \
../rhp_radius_attr_ms.c \
../rhp_radius_mesg.c \
../rhp_radius_misc.c \
../rhp_radius_session.c \
../rhp_radius_syspxy.c \
../rhp_radius_wpa_supplicant.c 

OBJS += \
./rhp_radius_attr.o \
./rhp_radius_attr_basic.o \
./rhp_radius_attr_eap.o \
./rhp_radius_attr_ms.o \
./rhp_radius_mesg.o \
./rhp_radius_misc.o \
./rhp_radius_session.o \
./rhp_radius_syspxy.o \
./rhp_radius_wpa_supplicant.o 

C_DEPS += \
./rhp_radius_attr.d \
./rhp_radius_attr_basic.d \
./rhp_radius_attr_eap.d \
./rhp_radius_attr_ms.d \
./rhp_radius_mesg.d \
./rhp_radius_misc.d \
./rhp_radius_session.d \
./rhp_radius_syspxy.d \
./rhp_radius_wpa_supplicant.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -D_GNU_SOURCE -D_REENTRANT -D_FORTIFY_SOURCE=1 -DRHP_MUTEX_DEBUG -DRHP_REFCNT_DEBUG -DRHP_LIBXML2 -I/usr/include/libxml2 -I../../include -O3 -g3 -Wall -c -fmessage-length=0 -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


