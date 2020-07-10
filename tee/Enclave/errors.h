#ifndef _ERRORS_H_
#define _ERRORS_H_

// ecall return values to the App
#define NO_ERROR  0
#define ERR_INVALID_OP_CODE 1
#define ERR_INVALID_CHANNEL 2
#define ERR_NO_CHANNEL 3
#define ERR_INVALID_PARAMS 4

const char* error_to_msg(int err);

#endif  // _ERRORS_H_