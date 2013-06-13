LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= \
	kallsymsprint.c
LOCAL_MODULE := kallsymsprint
LOCAL_CFLAGS += -std=c99
include $(BUILD_EXECUTABLE)
