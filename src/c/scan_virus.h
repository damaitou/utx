
#ifndef _SCAN_VIRUS_H
#define _SCAN_VIRUS_H

#include "clamav.h"
#include "clamav-types.h"
#include <string.h>

struct VirusScanner {

	struct cl_engine *cl_e;

};

extern unsigned long long vs_init();
extern int vs_scan(unsigned long long handle, const char *filename);

#endif

