#define _GNU_SOURCE
#include <dlfcn.h>
#include "time.h"
#include "faketime.h"

char frozen = 0;
time_t frozen_time = 0;

typedef time_t (*orig_time_f_type)(time_t*);
orig_time_f_type orig_time = NULL;

void _freeze(unsigned long time) {
	frozen_time = (time_t)time;
	frozen = 1;
}

void unfreeze() {
	frozen = 0;
}

time_t time(time_t *arg) {
	if (orig_time == NULL) {
		orig_time = (orig_time_f_type) dlsym(RTLD_NEXT, "time");
	}

	if (frozen) {
		if (arg) {
			*arg = frozen_time;
		}
		return frozen_time;
	} else {
		time_t time = orig_time(arg);
		return time;
	}
}
