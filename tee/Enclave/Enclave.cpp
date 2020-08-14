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
    unsigned long long amount = 1000000;

    // check the user exists
    map<string, Account*>::iterator iter = state.users.find(sender_addr);
    if (iter == state.users.end()) {
        // sender is not in the state, create new account
        Account* acc = new Account;
        acc->balance = 0;
        acc->nonce = 0;
        state.users[sender_addr] = acc;
    }

    // set user's balance
    state.users[sender_addr]->balance += amount;

    // increase state id
    state.stateID++;
    
    printf("new channel created with rouTEE -> user: %s / %balance:%llu\n", sender_addr.c_str(), amount);
    return NO_ERROR;
}

void ecall_print_state() {
    // print all the state: all users' address and balance
    printf("    owner address: %s\n", state.owner_address.c_str());
    printf("    routing fee: %llu\n", state.routing_fee);
    printf("    routing fee to %s\n", state.fee_address.c_str());
    for (map<string, Account*>::iterator iter = state.users.begin(); iter != state.users.end(); iter++){
        printf("    address: %s -> balance: %llu / nonce: %llu\n", (iter->first).c_str(), iter->second->balance, iter->second->nonce);
    }
    printf("    total %d accounts exist\n", state.users.size());

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
    map<string, Account*>::iterator iter = state.users.find(receiver_addr);
    if (iter == state.users.end() || iter->second->balance == 0) {
        // receiver is not in the state || has no balance
        return ERR_NOT_ENOUGH_BALANCE;
    }

    //
    // TODO: BITCOIN
    // make on-chain bitcoin tx
    // tx = make_settle_tx();
    // ocall_send_tx();
    //

    // set user's account
    printf("user %s get paid %llu satoshi\n", receiver_addr.c_str(), iter->second->balance);
    state.users[receiver_addr]->balance = 0;
    state.users[receiver_addr]->nonce++; // prevent payment replay attack

    //
    // TODO: commit pending fee to rouTEE operator (= fee address)
    //

    // increase state id
    state.stateID++;

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
    map<string, Account*>::iterator iter = state.users.find(sender_addr);
    if (iter == state.users.end() || iter->second->balance < amount + fee) {
        // sender is not in the state || has not enough balance
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // check routing fee
    if (fee < state.routing_fee) {
        return ERR_NOT_ENOUGH_FEE;
    }

    // check the receiver exists
    string receiver_addr = string(receiver_address, receiver_addr_len);
    iter = state.users.find(receiver_addr);
    if (iter == state.users.end()) {
        // receiver is not in the state, create new account
        Account* acc = new Account;
        acc->balance = 0;
        acc->nonce = 0;
        state.users[receiver_addr] = acc;
    }

    // move balance
    state.users[sender_addr]->balance -= (amount + fee);
    state.users[receiver_addr]->balance += amount;

    // set pending fees
    state.pending_fees[sender_addr] += fee/2;
    state.pending_fees[receiver_addr] += fee - fee/2;

    // increase sender's nonce
    state.users[sender_addr]->nonce++;

    // increase state id
    state.stateID++;

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

int ecall_seal_state(char* sealed_state, int* sealed_state_len) {

    // make state as a string
    string state_str = state.to_string();

    // seal the state
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)state_str.length());
    *sealed_state_len = sealed_data_size;
    if (sealed_data_size == UINT32_MAX) {
        return ERR_SGX_ERROR_UNEXPECTED;
    }
    sgx_sealed_data_t *sealed_state_buffer = (sgx_sealed_data_t *) malloc(sealed_data_size);
    sgx_status_t status = sgx_seal_data(0, NULL, (uint32_t)state_str.length(), (uint8_t *) state_str.c_str(), sealed_data_size, sealed_state_buffer);
    if (status != SGX_SUCCESS) {
        return ERR_SGX_ERROR_SEAL_FAILED;
    }

    // copy sealed state to the app buffer
    memcpy(sealed_state, sealed_state_buffer, sealed_data_size);
    free(sealed_state_buffer);
    return NO_ERROR;
}

int ecall_load_state(const char* sealed_state, int sealed_state_len) {
    // for edge8r
    (void) sealed_state_len;

    // unseal the sealed private key
    uint32_t unsealed_state_length = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *) sealed_state);
    uint8_t unsealed_state[unsealed_state_length];
    sgx_status_t status = sgx_unseal_data((const sgx_sealed_data_t *) sealed_state, NULL, 0, unsealed_state, &unsealed_state_length);
    if (status != SGX_SUCCESS) {
        return ERR_SGX_ERROR_UNSEAL_FAILED;
    }

    // load global state
    // state.owner_private_key.assign(unsealed_private_key, unsealed_private_key + unsealed_key_length);
    // printf("owner private key: %s\n", state.owner_private_key.c_str());
    string state_str;
    state_str.assign(unsealed_state, unsealed_state + unsealed_state_length);
    state.from_string(state_str);

    printf("success loading state!\n");

    return NO_ERROR;
}

void ecall_seal_channels() {
    // https://github.com/intel/linux-sgx/blob/master/SampleCode/SealUnseal/Enclave_Seal/Enclave_Seal.cpp
    // https://github.com/intel/linux-sgx/blob/master/SampleCode/SealUnseal/App/App.cpp
}

void ecall_unseal_channels() {
    
}
