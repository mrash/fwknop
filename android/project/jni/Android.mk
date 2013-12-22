# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH:= $(call my-dir)

# libfwknop module
#
include $(CLEAR_VARS)

LOCAL_MODULE    := libfwknop   

LOCAL_CFLAGS    := -W -g -DHAVE_CONFIG_H \
	-I$(LOCAL_PATH)/../../../common \
	-I$(LOCAL_PATH) \
	-I$(LOCAL_PATH)/fwknop \
	-I$(LOCAL_PATH)/libfwknop
LOCAL_SRC_FILES := $(shell cd $(LOCAL_PATH); \
		find ./fwknop/ -type f -name '*.c'; \
		find ./libfwknop/ -type f -name '*.c'; \
	)

LOCAL_LDLIBS    := \
                   -L$(LOCAL_PATH)/libs \
                   -llog

include $(BUILD_SHARED_LIBRARY)
