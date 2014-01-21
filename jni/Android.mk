#This library requires aihl library https://github.com/HiddenRambler/aihl

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := rootcloak
LOCAL_CFLAGS    := -std=c99 -Wall
LOCAL_SRC_FILES := rootcloak.c
LOCAL_LDLIBS    := -llog -ldl
LOCAL_STATIC_LIBRARIES := libaihl
LOCAL_C_INCLUDES = ../../aihl/jni
include $(BUILD_SHARED_LIBRARY)

include ../../aihl/jni/Android.mk
