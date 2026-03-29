
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include "scan_virus.h"

#define MAX_PATH_LEN (256)

int InitClamav(struct cl_engine **cl_e)
{
	unsigned int signo=0;

	int ret = cl_init(CL_INIT_DEFAULT);
	if(ret != CL_SUCCESS)
	{
		printf("cl_init fail ret %d %s\n",ret,cl_strerror(ret));
		return -1;
	}

	*cl_e = cl_engine_new();	
	if(*cl_e == NULL)
	{
		printf("cl_engine_new fail ret %d %s\n",ret,cl_strerror(ret));
		return -1;
	}

	 /* load all available databases from default directory */
	printf("cl_load databases starting \n");
	ret = cl_load(cl_retdbdir(), *cl_e, &signo, CL_DB_STDOPT);
	if(ret != CL_SUCCESS)
	{
		printf("cl_load or cl_retdbdir fail ret %d %s\n",ret,cl_strerror(ret));
		cl_engine_free(*cl_e);
		return -1;
	}
	printf("cl_load databases finished \n");
		
	ret = cl_engine_compile(*cl_e);
	if(ret != CL_SUCCESS)
	{
		printf("cl_engine_compile fail ret %d %s\n",ret,cl_strerror(ret));
		cl_engine_free(*cl_e);
		return -1;
	}	
	printf("InitClamav successed \n");
	
	return 0;
}

unsigned long long vs_init()
{
    struct VirusScanner *vs = (struct VirusScanner *) malloc (sizeof(struct VirusScanner));
    if (NULL == vs)
        return 0;

    vs->cl_e = NULL;
	int ret = 0;
	
	ret = InitClamav(&vs->cl_e);
	if(ret != 0) {
		printf("InitClamav fail ret %d\n",ret);
        free((void *)vs);
		return 0;
	}

    return (unsigned long long)vs;
}

int vs_scan(unsigned long long handle, const char *filename)
{
    struct VirusScanner *vs = (struct VirusScanner *) handle;
    if (NULL == vs)
        return -1;

    struct cl_scan_options options;
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0; // enable all parsers 
    options.general |= CL_SCAN_GENERAL_HEURISTICS; // enable heuristic alert options 

    const char virname[128]={0};
    long unsigned int scanned = 0;
    int ret;
    ret = cl_scanfile(filename,(const char **)&virname,&scanned,vs->cl_e,&options);
    if(ret == CL_CLEAN) {
        //printf("No virus detected.\n");
        return 1;
    } else {
        printf("Error: %s\n", cl_strerror(ret)); //todo
        return 0;
    }
}

