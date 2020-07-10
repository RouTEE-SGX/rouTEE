#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C"{
#endif

void printf(const char* fmt, ...);

//
// Ecalls
//

// just print "hello world"
void printf_helloworld();

// add my channel to rouTEE (= deposit)
int ecall_add_channel(const char* tx_id, int tx_id_len, unsigned int tx_index);

// print all channels
void ecall_print_channels();

// seal all channels
void ecall_seal_channels();

// unseal all channels
void ecall_unseal_channels();

// remove my channel from rouTEE (= withdraw)
int ecall_remove_channel(const char* target_channel_id, int ch_id_len);

// request payment for my channel
int ecall_do_payment(const char* channel_id, int ch_id_len, const char* sender_address, int address_len, unsigned long long amount);

// request for multi hop payment (need routing fee)
int ecall_do_multihop_payment();

// check my balance in the channel
int ecall_get_channel_balance();

#if defined(__cplusplus)
}
#endif

#endif // _ENCLAVE_H_
