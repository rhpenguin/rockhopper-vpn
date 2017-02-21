################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: rockhopperd

# Tool invocations
rockhopperd: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc -L"../../../rhptrace/lib" -L"../../librhplog_def/build" -L"../../librhpcrypto_openssl/build" -L"../../librhpcert_openssl/build" -L"../../librhpesp_def/build" -L"../../librhpeapa_def/build" -L"../../librhpeaps_def/build" -L"../../librhpradius_def/build" -L"../../librhpbfltr/build" -L"../../librhppcap_def/build" -o"rockhopperd" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C_DEPS)$(EXECUTABLES) rockhopperd
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
