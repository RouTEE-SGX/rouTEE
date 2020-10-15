#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"  // sgx_status_t
#include "sgx_eid.h"    // sgx_enclave_id_t

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TOKEN_FILENAME  "enclave.token"
#define ENCLAVE_FILENAME    "enclave.signed.so"
#define OWNER_KEY_FILENAME "owner.key.encrypted"
#define STATE_FILENAME  "state.encrypted"
#define MAX_SEALED_DATA_LENGTH   1000000

#define STATE_SAVE_EPOCH    0 // 0 means do not save state
int state_save_counter = 0;

#define MAX_MSG_SIZE    1024
#define MAX_CLIENTS 30
#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 7223

extern sgx_enclave_id_t global_eid; // global enclave id (from routee.cpp)

// tell C++ compiler that use C style linkage method for below functions
#if defined(__cplusplus)
extern "C" {
#endif
// function declarations
// void edger8r_array_attributes(void);
// void ecall_libc_functions(void);
#if defined(__cplusplus)
}
#endif

#endif  // _APP_H
