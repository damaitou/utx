
#include "handler.h"

utx_handler_t hands[32] = {
  0,				//UTX_TYPE_TEST 0
  handle_datagram,		//UTX_TYPE_DATAGRAM 1
  handle_block, 		//UTX_TYPE_BLOCK 2 
  handle_file,			//UTX_TYPE_FILE 3
};
