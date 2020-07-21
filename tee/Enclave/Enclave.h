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

// print all channels (just for debugging)
void ecall_print_channels();

// seal all channels
void ecall_seal_channels();

// unseal all channels
void ecall_unseal_channels();

// remove my channel from rouTEE (= withdraw)
int ecall_remove_channel(const char* target_channel_id, int ch_id_len);

// request payment for my channel
int ecall_do_payment(const char* channel_id, int ch_id_len, const char* sender_address, int address_len, unsigned long long amount);

// set routing fee
int ecall_set_routing_fee(unsigned long long fee);

// set routing fee address
int ecall_set_routing_fee_address(const char* fee_address, int fee_addr_len);

// create a channel with rouTEE (send BTC to owner key)
int ecall_create_channel(const char* tx_id, int tx_id_len, unsigned int tx_index);

// print all users' address & balance (just for debugging)
void ecall_print_state();

// take my balance at on-chain
int ecall_settle_balance(const char* receiver_address, int receiver_addr_len);

// request rouTEE 2 hop payment (need routing fee)
int ecall_do_multihop_payment(const char* sender_address, int sender_addr_len, const char* receiver_address, int receiver_addr_len, unsigned long long amount, unsigned long long fee);

// save randomly created and encrypted owner key
int ecall_make_owner_key(char* sealed_owner_private_key, int* sealed_key_len);

// decrypt the encrypted owner key file & load it into the enclave
int ecall_load_owner_key(const char* sealed_owner_private_key, int sealed_key_len);

// check my balance in the channel
unsigned long long ecall_get_channel_balance(const char* channel_id, int ch_id_len, const char* user_address, int address_len);

#if defined(__cplusplus)
}
#endif

#endif // _ENCLAVE_H_
