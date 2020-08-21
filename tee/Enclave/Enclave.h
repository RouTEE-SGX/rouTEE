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

// set routing fee
int ecall_set_routing_fee(unsigned long long fee);

// set routing fee address
int ecall_set_routing_fee_address(const char* fee_address, int fee_addr_len);

// create a channel with rouTEE (send BTC to owner key)
int ecall_create_channel(const char* tx_id, int tx_id_len, unsigned int tx_index);

// print all users' address & balance (just for debugging)
void ecall_print_state();

// settle request
int ecall_settle_balance(const char* receiver_address, int receiver_addr_len);

// create on-chain settle transaction
int ecall_make_settle_transaction(const char* settle_transaction, int* settle_tx_len);

// request rouTEE 2 hop payment (need routing fee)
int ecall_do_multihop_payment(const char* sender_address, int sender_addr_len, const char* receiver_address, int receiver_addr_len, unsigned long long amount, unsigned long long fee);

// insert blockchain's block (for SPV inside TEE)
int ecall_insert_block(const char* block, int block_len);

// save randomly created and encrypted owner key
int ecall_make_owner_key(char* sealed_owner_private_key, int* sealed_key_len);

// decrypt the encrypted owner key file & load it into the enclave
int ecall_load_owner_key(const char* sealed_owner_private_key, int sealed_key_len);

// seal current state
int ecall_seal_state(char* sealed_state, int* sealed_state_len);

// load state from sealed data
int ecall_load_state(const char* sealed_state, int sealed_state_len);

#if defined(__cplusplus)
}
#endif

#endif // _ENCLAVE_H_
