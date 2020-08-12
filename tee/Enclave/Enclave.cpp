#include <stdarg.h>
#include <stdio.h>

#include "Enclave.h"
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "channel.h"
#include "errors.h"
#include "state.h"
#include "utils.h"

// user address to the user's channels
map<string, vector<Channel*>> addresses_to_channels;

// map[channel_id] = Channel*
map<string, Channel*> channels;

// global state
State state;

// invoke OCall to display the enclave buffer to the terminal screen
void printf(const char* fmt, ...) {

    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf); // OCall
}

// Ecall: print hello world to the terminal screen
void printf_helloworld() {
    printf("Hello World!\n");
}

int ecall_set_routing_fee(unsigned long long fee){
    //
    // TODO: BITCOIN
    // check authority to set new routing fee (ex. routing_fee_address's signature)
    // if (cannot set new routing fee) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    state.routing_fee = fee;
    return NO_ERROR;
}

int ecall_set_routing_fee_address(const char* fee_address, int fee_addr_len){
    //
    // TODO: BITCOIN
    // check authority to set new routing fee address (ex. older routing_fee_address's signature)
    // if (cannot set new routing fee address) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    state.fee_address = string(fee_address, fee_addr_len);
    return NO_ERROR;
}

int ecall_create_channel(const char* tx_id, int tx_id_len, unsigned int tx_index) {
    
    // 
    // TODO: BITCOIN
    // get this tx info (receiver) & compare the tx receiver vs rouTEE owner key
    // 
    // temp code
    string receiver_addr = "";
    if (receiver_addr != state.owner_address) {
        return ERR_INVALID_RECEIVER;
    }

    // 
    // TODO: BITCOIN
    // get this tx info (ex. sender address & amount)
    //
    // temp code
    string sender_addr = string(tx_id, tx_id_len) + "_" + long_long_to_string(tx_index);
    unsigned long long amount = 100;

    // add user's balance
    state.user_balances[sender_addr] += amount;
    
    printf("new channel created with rouTEE -> user: %s / %balance:%llu\n", sender_addr.c_str(), amount);
    return NO_ERROR;
}

void ecall_print_state() {
    // print all the state: all users' address and balance
    printf("    owner address: %s\n", state.owner_address.c_str());
    printf("    routing fee: %llu\n", state.routing_fee);
    printf("    routing fee to %s\n", state.fee_address.c_str());
    for (map<string, unsigned long long>::iterator iter = state.user_balances.begin(); iter != state.user_balances.end(); iter++){
        printf("    user %s balance: %llu\n", (iter->first).c_str(), iter->second);
    }
    return;
}

int ecall_settle_balance(const char* receiver_address, int receiver_addr_len) {
    //
    // TODO: BITCOIN
    // check authority to get paid the balance (ex. receiver's signature with settlement params)
    // if (no authority to get balance) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    // check the receiver has more than 0 balance
    string receiver_addr = string(receiver_address, receiver_addr_len);
    map<string, unsigned long long>::iterator iter = state.user_balances.find(receiver_addr);
    if (iter == state.user_balances.end() || iter->second == 0) {
        // receiver is not in the state || has no balance
        return ERR_NOT_ENOUGH_BALANCE;
    }

    //
    // TODO: BITCOIN
    // make on-chain bitcoin tx
    // tx = make_settle_tx();
    // ocall_send_tx();
    //

    // remove the user from the state
    printf("user %s get paid %llu satoshi\n", receiver_addr.c_str(), iter->second);
    state.user_balances.erase(receiver_addr);
    return NO_ERROR;
}

int ecall_do_multihop_payment(const char* sender_address, int sender_addr_len, const char* receiver_address, int receiver_addr_len, unsigned long long amount, unsigned long long fee) {
    //
    // TODO: BITCOIN
    // check authority to send (ex. sender's signature with these params)
    // if (no authority to send) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    // check the sender has more than amount + fee to send
    string sender_addr = string(sender_address, sender_addr_len);
    map<string, unsigned long long>::iterator iter = state.user_balances.find(sender_addr);
    if (iter == state.user_balances.end() || iter->second < amount + fee) {
        // sender is not in the state || has not enough balance
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // check routing fee
    if (fee < state.routing_fee) {
        return ERR_NOT_ENOUGH_FEE;
    }

    // move balance
    string receiver_addr = string(receiver_address, receiver_addr_len);
    state.user_balances[sender_addr] -= (amount + fee);
    state.user_balances[receiver_addr] += amount;
    // state.user_balances[state.fee_address] += fee;
    state.pending_fees[receiver_addr] += fee;

    // remove 0 balance sender from the state
    if (state.user_balances[sender_addr] == 0) {
        state.user_balances.erase(sender_addr);
    }
    
    printf("send %llu from %s to %s / fee %llu to %s\n", amount, sender_addr.c_str(), receiver_addr.c_str(), fee, state.fee_address.c_str());
    return NO_ERROR;
}

int ecall_make_owner_key(char* sealed_owner_private_key, int* sealed_key_len) {
    //
    // TODO: BITCOIN
    // make random bitcoin private key
    //
    char random_private_key[300] = "abcde"; // temp code
    printf("random private key: %s\n", random_private_key);

    // seal the private key
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(random_private_key));
    *sealed_key_len = sealed_data_size;
    if (sealed_data_size == UINT32_MAX) {
        return ERR_SGX_ERROR_UNEXPECTED;
    }
    sgx_sealed_data_t *sealed_key_buffer = (sgx_sealed_data_t *) malloc(sealed_data_size);
    sgx_status_t status = sgx_seal_data(0, NULL, (uint32_t)strlen(random_private_key), (uint8_t *) random_private_key, sealed_data_size, sealed_key_buffer);
    if (status != SGX_SUCCESS) {
        return ERR_SGX_ERROR_SEAL_FAILED;
    }

    // copy sealed key to the app buffer
    memcpy(sealed_owner_private_key, sealed_key_buffer, sealed_data_size);
    free(sealed_key_buffer);
    return NO_ERROR;
}

int ecall_load_owner_key(const char* sealed_owner_private_key, int sealed_key_len) {
    // for edge8r
    (void) sealed_key_len;

    // unseal the sealed private key
    uint32_t unsealed_key_length = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *) sealed_owner_private_key);
    uint8_t unsealed_private_key[unsealed_key_length];
    sgx_status_t status = sgx_unseal_data((const sgx_sealed_data_t *) sealed_owner_private_key, NULL, 0, unsealed_private_key, &unsealed_key_length);
    if (status != SGX_SUCCESS) {
        return ERR_SGX_ERROR_UNSEAL_FAILED;
    }

    // set owner_private_key
    state.owner_private_key.assign(unsealed_private_key, unsealed_private_key + unsealed_key_length);
    printf("owner private key: %s\n", state.owner_private_key.c_str());

    //
    // TODO: BITCOIN
    // set owner_public_key & owner_address
    // 

    return NO_ERROR;
}

void ecall_seal_channels() {
    // https://github.com/intel/linux-sgx/blob/master/SampleCode/SealUnseal/Enclave_Seal/Enclave_Seal.cpp
    // https://github.com/intel/linux-sgx/blob/master/SampleCode/SealUnseal/App/App.cpp
}

void ecall_unseal_channels() {
    
}
