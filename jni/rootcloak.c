/*

Copyright (C) 2014 rambler@hiddenramblings.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <aihl.h>

#define LOG_TAG "libbarcxposedhook.so"

void __attribute__ ((constructor)) lib_on_load(void);

int logcat_logger(const char *format, ...) {
	va_list args;
	va_start(args, format);
	__android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
	va_end(args);
	return 0;
}

int system_hook(const char *command) {
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, ">>>System invoked: %s", command);
	return system("suww");
}

FILE *fopen_hook(const char *path, const char *mode) {
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, ">>>fopen invoked: %s", path);
	if (!strcmp(path, "/proc/self/maps")) {
		return fopen("/proc/1/maps", mode);
	}
	if (!strcmp(path, "/data/sample.txt")) {
		return NULL;
	}
	return fopen(path, mode);
}

int stat_hook(const char *path, struct stat *buf) {
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, ">>>stat invoked: %s", path);

	if (!strcmp("/system/bin/su", path) ||
		!strcmp("/system/xbin/su", path) ||
		!strcmp("su", path) ||
		!strcmp("daemonsu", path) ||

		!strcmp("/system/bin/amphoras", path) ||
		!strcmp("/system/xbin/amphoras", path) ||
		!strcmp("/system/app/superuser.apk", path) ||
		!strcmp("/data/data/com.amphoras.hidemyroot", path) ||
		!strcmp("/data/data/eu.chainfire.supersu", path) ||
		!strcmp("/data/data/stericson.busybox", path) ||
		!strcmp("/data/data/stericson.busybox.donate", path) ||
		!strcmp("/data/data/com.jrummy.busybox.installer.pro", path) ||
		!strcmp("/data/data/com.jrummy.busybox.installer", path) ||
		!strcmp("/system/lib/libsubstrate.so", path) ||
		!strcmp("/vendor/lib/liblog!.so", path)) {
		__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, ">>>changing stat path for root app");
		return stat("/system/bin/nosuhere", buf);
	}

	int res = stat(path, buf);
	if (buf->st_mode & S_ISUID || buf->st_mode & S_ISGID || buf->st_mode & S_ISVTX) {
		printf(">>> hiding sticky bit\n");
		buf->st_mode &= ~(S_ISUID | S_ISGID | S_ISVTX);
	}
	return res;
}

FILE *popen_hook(const char *command, const char *type) {
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, ">>>popen invoked: %s", command);

	if (!strncmp("pm path", command, 7)) {
		__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, ">>>popen redirected");
		return popen("echo", type);
	}
	if (!strncmp("ps 2>&1", command, 7)) {
		__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, ">>>popen redirected (ps)");
		return popen("ps -p 1 2>&1", type);
	}

	return popen(command, type);
}

void patch_system_calls() {
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Patching system calls");

	void *libchandle = aihl_load_library("libc.so");
    aihl_hook_symbol(libchandle, "fopen", fopen_hook);
    aihl_hook_symbol(libchandle, "system", system_hook);
    aihl_hook_symbol(libchandle, "stat", stat_hook);
    aihl_hook_symbol(libchandle, "popen", popen_hook);

	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "hooktest: patching complete");
}

void lib_on_load(void) {
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "hook library loaded");
    aihl_set_log_func(logcat_logger);
	patch_system_calls();
}

