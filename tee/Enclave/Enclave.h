#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C"{
#endif

void printf(const char *fmt, ...);

// Ecalls
void printf_helloworld();
int ecall_add_channel(const char* tx_id, int tx_id_len, unsigned int tx_index);            // add his channel to rouTEE (= deposit)
void ecall_print_channels();        // print all channels
void ecall_seal_channels();         // seal all channels
void ecall_unseal_channels();       // unseal all channels
int ecall_remove_channel(const char *target_channel_id, int ch_id_len);         // remove his channel from rouTEE (= withdraw)
int ecall_do_payment(const char *channel_id, int ch_id_len, const char *sender_address, int address_len, unsigned long long amount);             // request for his channel payment
int ecall_do_multihop_payment();    // request for multi hop payment (need routing fee)
int ecall_get_channel_balance();    // check his channel's balance

#if defined(__cplusplus)
}
#endif

#endif // _ENCLAVE_H_
