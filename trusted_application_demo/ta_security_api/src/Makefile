CFG_TEE_TA_LOG_LEVEL = 2
# This should match the value of TA_TRUSTED_UUID in ta_public.h
BINARY ?= aed3b02c-8e42-11e7-bb31be2e44b06b34

# Will be used for all the compilation rules
# sub.mk is called for all the include and source specification
-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: $(BINARY).ta

clean: clean_ta_file
.PHONY: clean_ta_file
clean_ta_file:
	rm -f $(BINARY).*
	rm -f *.o
	rm -f *.o.*
	rm -f *.d
	rm -f *.cmd
	rm -f *.lds
	rm -f .*.d
	rm -f .*.cmd
