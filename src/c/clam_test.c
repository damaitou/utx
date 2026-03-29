#include "clamav.h"
#include "clamav-types.h"
#include <string.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX_PATH_LEN (256)

void DetectDir(struct cl_engine *cl_e,char *path,struct cl_scan_options *options){
    DIR *d = NULL;
    struct dirent *dp = NULL; /* readdir函数的返回值就存放在这个结构体中 */
    struct stat st;    
    char p[MAX_PATH_LEN] = {0};
    
    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("invalid path: %s\n", path);
        return;
    }

    if(!(d = opendir(path))) {
        printf("opendir[%s] error: %m\n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        /* 把当前目录.，上一级目录..及隐藏文件都去掉，避免死循环遍历目录 */
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;

        snprintf(p, sizeof(p) - 1, "%s/%s", path, dp->d_name);
        stat(p, &st);
        if(!S_ISDIR(st.st_mode)) {
			char virname[64]={0};
			int scanned = 0;
			int ret = cl_scanfile(p,&virname,&scanned,cl_e,&options);
            printf("%s\n",p);

			if(ret == CL_CLEAN) {
	    		printf("No virus detected.\n");
			} else {
	    		printf("Error: %s\n", cl_strerror(ret));	
			}

   		 	long double mb;

		 	/* calculate size of scanned data */
    		mb = scanned * (CL_COUNT_PRECISION / 1024) / 1024.0;
    		printf("Data scanned: %2.2Lf MB\n", mb);
			
        } 
		else {
         //   printf("%s\n", dp->d_name);
         
            DetectDir(cl_e,p,&options);
        }
    }
    closedir(d);

    return;
}

int InitClamav(struct cl_engine **cl_e)
{
	int signo=0;

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
		cl_engine_free(cl_e);
		return -1;
	}
	printf("cl_load databases finished \n");
		
	ret = cl_engine_compile(*cl_e);
	if(ret != CL_SUCCESS)
	{
		printf("cl_engine_compile fail ret %d %s\n",ret,cl_strerror(ret));
		cl_engine_free(cl_e);
		return -1;
	}	
	printf("InitClamav successed \n");
	
	return 0;
}

int main(int argc, char **argv)
{   
    char *path = NULL;
 
    if (argc != 2) {
        printf("Usage: %s [dir]\n", argv[0]);
        printf("use DEFAULT option: %s .\n", argv[0]);
        printf("-------------------------------------------\n");
        path = "./";
    } else {
        path = argv[1];
    }

	struct cl_engine *cl_e = NULL;
	int ret = 0;
	
	ret = InitClamav(&cl_e);
	if(ret != 0)
	{
		printf("InitClamav fail ret %d\n",ret);
		return -1;
	}	

	  /* scan file descriptor */
	
	struct cl_scan_options options;
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0; /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS; /* enable heuristic alert options */

	char *filename= "/root/ftpc.c";
	char virname[64]={0};
	long int scanned = 0;

	if(cl_e != NULL){
		
		ret = cl_scanfile(filename,&virname,&scanned,cl_e,&options);
		if(ret == CL_CLEAN) {
	    	printf("No virus detected.\n");
		} else {
	    	printf("Error: %s\n", cl_strerror(ret));
	    	cl_engine_free(cl_e);
	   	 return -1;
		}

   		 long double mb;

		 /* calculate size of scanned data */
    	mb = scanned * (CL_COUNT_PRECISION / 1024) / 1024.0;
    	printf("Data scanned: %2.2Lf MB\n", mb);
	
		DetectDir(cl_e,path,&options);
	}
   
    return 0;
}
