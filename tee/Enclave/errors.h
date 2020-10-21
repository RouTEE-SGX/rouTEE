#ifndef _ERRORS_H_
#define _ERRORS_H_

// ecall return values to the App
#define NO_ERROR  0
#define ERR_INVALID_OP_CODE 1
#define ERR_INVALID_CHANNEL 2
#define ERR_NO_CHANNEL 3
#define ERR_INVALID_PARAMS 4
#define ERR_INVALID_USER 5
#define ERR_NOT_ENOUGH_BALANCE 6
#define ERR_ALREADY_EXIST_CHANNEL 7
#define ERR_INVALID_RECEIVER 8
#define ERR_NOT_ENOUGH_FEE 9
#define ERR_SGX_ERROR_UNEXPECTED 10
#define ERR_SGX_ERROR_SEAL_FAILED 11
#define ERR_SGX_ERROR_UNSEAL_FAILED 12
#define ERR_SGX_ERROR_DECRYPT_FAILED 13

#define MAX_UNSIGNED_LONG_LONG 9223372036854775807

// get the error message for the error index
const char* error_to_msg(int err);

#endif  // _ERRORS_H_