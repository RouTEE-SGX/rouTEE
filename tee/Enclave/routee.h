#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

// bitcoin constants
#define BITCOIN_ADDRESS_LEN 34
#define BITCOIN_PUBLIC_KEY_LEN 66
#define BITCOIN_PRIVATE_KEY_LEN 52
#define BITCOIN_TX_HASH_LEN 64
#define BITCOIN_TX_SCRIPT_LEN 50

#define SATOSHI_PER_BITCOIN 100000000

#define MAX_NUM_STR_LENGTH 100

#if defined(__cplusplus)
extern "C"{
#endif

void printf(const char* fmt, ...);

//
// Ecalls
//

// set routing fee
int ecall_set_routing_fee(const char* command, int cmd_len, const char* signature, int sig_len);

// set routing fee address
int ecall_set_routing_fee_address(const char* command, int cmd_len, const char* signature, int sig_len);

// settle request for routing fee
int ecall_settle_routing_fee(const char* command, int cmd_len, const char* signature, int sig_len);

// print all users' address & balance (just for debugging)
void ecall_print_state();

// create on-chain settle transaction
int ecall_make_settle_transaction(const char* settle_transaction, int* settle_tx_len);

// insert blockchain's block (for SPV inside TEE)
int ecall_insert_block(int block_num, const char* hex_block, int hex_block_len);

// give encrypted command to rouTEE
int ecall_secure_command(const char* sessionID, int sessionID_len, const char* encrypted_cmd, int encrypted_cmd_len, char* encrypted_response, int* encrypted_response_len);

// save randomly created and encrypted owner key
int ecall_make_owner_key(char* sealed_owner_private_key, int* sealed_key_len);

// decrypt the encrypted owner key file & load it into the enclave
int ecall_load_owner_key(const char* sealed_owner_private_key, int sealed_key_len);

// seal current state
int ecall_seal_state(char* sealed_state, int* sealed_state_len);

// load state from sealed data
int ecall_load_state(const char* sealed_state, int sealed_state_len);



//
// Ecalls functions for debugging
//

void deal_with_deposit_tx(const char* manager_address, int manager_addr_len, const char* txid, int txid_len, int tx_index, unsigned long long amount, unsigned long long block_number);
void deal_with_settlement_tx();

#if defined(__cplusplus)
}
#endif

#endif // _ENCLAVE_H_
