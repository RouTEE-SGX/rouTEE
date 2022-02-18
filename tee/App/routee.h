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
#define ENCLAVE_FILENAME    "routee.signed.so"
#define STATE_FILENAME  "state.sealed"
#define MAX_SEALED_DATA_LENGTH   30001000
#define MAX_TX_SIZE 1000000
#define MAX_ENCRYPTED_RESPONSE_LENGTH 200
#define MAX_SEALED_KEY_LENGTH 1000

#define STATE_SAVE_EPOCH    0 // 0 means do not save state
int state_save_counter = 0;

#define MAX_MSG_SIZE    4096
#define MAX_CLIENTS 100
#define SERVER_IP   "172.17.0.3" // docker IP address ($ ip addr show eth0)
#define SERVER_PORT 7557         // if want to kill -> $ sudo kill -9 $(sudo lsof -t -i:7557)

#define NEGLECT_COUNT   0
#define PRINT_EPOCH     10000

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
