LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= \
	main.c
LOCAL_MODULE := kallsymsprint
LOCAL_CFLAGS += -std=c99
LOCAL_STATIC_LIBRARIES += libkallsyms

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
