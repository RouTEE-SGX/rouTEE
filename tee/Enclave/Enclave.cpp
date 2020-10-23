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
#include "network.h"

#define SGX_AESGCM_MAC_SIZE 16 // bytes
#define SGX_AESGCM_IV_SIZE 12 // bytes
#define BUFLEN 2048

#include <sgx_thread.h>
sgx_thread_mutex_t state_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
    unsigned long long amount = 100000000;

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
    
    printf("new channel created with rouTEE -> user: %s / balance: %llu\n", sender_addr.c_str(), amount);
    return NO_ERROR;
}

// operation function for secure_command
// ecall_create_channel() function should be removed later
int secure_create_channel(const char* tx_id, int tx_id_len, unsigned int tx_index) {
    
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
    unsigned long long amount = 100000000;

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
    
    printf("new channel created with rouTEE -> user: %s / balance: %llu\n", sender_addr.c_str(), amount);
    return NO_ERROR;

    // 
    // above code is just for debugging
    // 
    // real implementation for secure_ready_for_deposit()
    // 1. params: sender's settlement address
    // 2. return: randomly genereated address to receive deposit from sender & latest block info in rouTEE header chain
    //

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

    for (int i = 0; i < state.settle_requests.size(); i++) {
        printf("    user %s settles %llu satoshi\n", state.settle_requests[i].address, state.settle_requests[i].amount);
    }

    for (map<string, unsigned long long>::iterator iter = state.pending_fees.begin(); iter != state.pending_fees.end(); iter++){
        printf("    user %s pending fee: %llu satoshi\n", iter->first.c_str(), iter->second);
    }

    return;
}

int ecall_settle_balance(const char* user_address, int user_addr_len) {
    //
    // TODO: BITCOIN
    // check authority to get paid the balance (ex. user's signature with settlement params)
    // if (no authority to get balance) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    // check the user has more than 0 balance
    string user_addr = string(user_address, user_addr_len);
    map<string, Account*>::iterator iter = state.users.find(user_addr);
    if (iter == state.users.end() || iter->second->balance == 0) {
        // user is not in the state || has no balance
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // push new settle request
    state.settle_requests.push_back(SettleRequest());
    state.settle_requests.back().address = user_addr;
    state.settle_requests.back().amount = iter->second->balance;

    // set user's account
    printf("user %s requests settlement: %llu satoshi\n", user_addr.c_str(), iter->second->balance);
    state.users[user_addr]->balance = 0;
    state.users[user_addr]->nonce++; // prevent payment replay attack    

    //
    // TODO: commit pending fee to rouTEE operator (= fee address)
    //

    // increase state id
    state.stateID++;

    return NO_ERROR;
}

// operation function for secure_command
// ecall_settle_balance() function should be removed later
int secure_settle_balance(const char* user_address, int user_addr_len) {
    //
    // TODO: BITCOIN
    // check authority to get paid the balance (ex. user's signature with settlement params)
    // if (no authority to get balance) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    // check the user has more than 0 balance
    string user_addr = string(user_address, user_addr_len);
    map<string, Account*>::iterator iter = state.users.find(user_addr);
    if (iter == state.users.end() || iter->second->balance == 0) {
        // user is not in the state || has no balance
        return ERR_NOT_ENOUGH_BALANCE;
    }
    Account* user_acc = iter->second;

    // push new settle request
    state.settle_requests.push_back(SettleRequest());
    state.settle_requests.back().address = user_addr;
    state.settle_requests.back().amount = user_acc->balance;

    // set user's account
    printf("user %s requests settlement: %llu satoshi\n", user_addr.c_str(), user_acc->balance);
    user_acc->balance = 0;
    user_acc->nonce++; // prevent payment replay attack    

    //
    // TODO: commit pending fee to rouTEE operator (= fee address)
    //

    // increase state id
    state.stateID++;

    return NO_ERROR;
}

int ecall_make_settle_transaction(const char* settle_transaction, int* settle_tx_len) {

    //
    // TODO: BITCOIN
    // check last settle tx has committed at on-chain (before 6 blocks)
    // if (not ready to make settle tx) {
    //     return ERR_CANNOT_MAKE_SETTLE_TX;
    // }
    //

    // calculate proper pending fees for this settle tx
    unsigned long long committed_pending_fee = 0;
    string settle_user_addr;
    unsigned long long settle_amount;
    for (int i = 0; i < state.settle_requests.size(); i++) {
        // get settle user info
        settle_user_addr = state.settle_requests[i].address;
        settle_amount = state.settle_requests[i].amount;

        // deal with pending fees
        committed_pending_fee += state.pending_fees[settle_user_addr];
        state.pending_fees.erase(settle_user_addr);
    }

    // push new settle request for rouTEE's fee address
    state.settle_requests.push_back(SettleRequest());
    state.settle_requests.back().address = state.fee_address;
    state.settle_requests.back().amount = committed_pending_fee;

    //
    // TODO: BITCOIN
    // make on-chain bitcoin tx
    // *settle_transaction = make_settle_tx(state.settle_requests);
    // *settle_tx_len = len(settle_transaction);
    // 

    // delete all settle requests
    state.settle_requests.clear();
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

// operation function for secure_command
// ecall_do_multihop_payment() function should be removed later
int secure_do_multihop_payment(const char* sender_address, int sender_addr_len, const char* receiver_address, int receiver_addr_len, unsigned long long amount, unsigned long long fee) {
    //
    // TODO: BITCOIN
    // check authority to send (ex. sender's signature with these params)
    // if (no authority to send) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    // check the sender exists & has more than amount + fee to send
    string sender_addr = string(sender_address, sender_addr_len);
    map<string, Account*>::iterator iter = state.users.find(sender_addr);
    if (iter == state.users.end() || iter->second->balance < amount + fee) {
        // sender is not in the state || has not enough balance
        return ERR_NOT_ENOUGH_BALANCE;
    }
    Account* sender_acc = iter->second;

    // check routing fee
    if (fee < state.routing_fee) {
        return ERR_NOT_ENOUGH_FEE;
    }

    // check the receiver exists
    string receiver_addr = string(receiver_address, receiver_addr_len);
    iter = state.users.find(receiver_addr);
    if (iter == state.users.end()) {
        // receiver is not in the state
        return ERR_NO_RECEIVER;
    }
    Account* receiver_acc = iter->second;

    // check the receiver is ready to get paid (temporarily deprecated for easy tests)
    // if (sender_acc->min_requested_block_number > receiver_acc->latest_SPV_block_number) {
    //     return ERR_RECEIVER_NOT_READY;
    // }

    // move balance
    sender_acc->balance -= (amount + fee);
    receiver_acc->balance += amount;

    // set pending fees
    state.pending_fees[sender_addr] += fee/2;
    state.pending_fees[receiver_addr] += fee - fee/2;

    // increase sender's nonce
    sender_acc->nonce++;

    // update receiver's requested_block_number
    if (receiver_acc->min_requested_block_number < sender_acc->min_requested_block_number) {
        receiver_acc->min_requested_block_number = sender_acc->min_requested_block_number;
    }

    // update sender's requested_block_number
    if (sender_acc->balance == 0) {
        // sender spent all balance -> reset min requested block number
        sender_acc->min_requested_block_number = 0;
    }

    // increase state id
    state.stateID++;

    printf("send %llu from %s to %s / fee %llu to %s\n", amount, sender_addr.c_str(), receiver_addr.c_str(), fee, state.fee_address.c_str());
    return NO_ERROR;
}

// update user's latest SPV block
int secure_update_latest_SPV_block(string user_address, int user_addr_len, unsigned long long block_number) {

    // check the user exists
    string user_addr = string(user_address, user_addr_len);
    map<string, Account*>::iterator iter = state.users.find(user_addr);
    if (iter == state.users.end()) {
        // the user not exist
        return ERR_ADDRESS_NOT_EXIST;
    }
    Account* user_acc = iter->second;

    // check user has same block with rouTEE
    // if () {
    //     ;
    // }

    // check the block number is larger than user's previous latest block number
    if (user_acc->latest_SPV_block_number < block_number) {
        // update block number
        user_acc->latest_SPV_block_number = block_number;
    }    
    
    return NO_ERROR;
}

int ecall_insert_block(const char* block, int block_len) {
    // 
    // TODO: BITCOIN
    // SPV verify the new bitcoin block
    // verify tx merkle root hash
    // iterate txs to find deposit tx to update user balance state
    //             to find settle tx to give pending routing fee to rouTEE host's fee address
    // 
}

int make_encrypted_response(int result_error_index, sgx_aes_gcm_128bit_key_t *session_key, char* encrypted_response, int* encrypted_response_len) {
    // return encrypted response to client
    const char* response_msg = error_to_msg(result_error_index);
    printf("response_msg: %s\n", response_msg);
    uint8_t *response = (uint8_t *) response_msg;
    size_t len = strlen(response_msg);
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

    // encrypt the response
	sgx_status_t status = sgx_rijndael128GCM_encrypt(
		session_key,
		response, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE,
        SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst)
    );

    // check encryption result
    if (status != SGX_SUCCESS) {
        // encryption failed: abnormal case
        // this cannot be happened in ordinary situations
        // SGX_ERROR_INVALID_PARAMETER || SGX_ERROR_OUT_OF_MEMORY || SGX_ERROR_UNEXPECTED
        return ERR_ENCRYPT_FAILED;
    }

    // copy encrypted response to outside buffer
    *encrypted_response_len = SGX_AESGCM_MAC_SIZE+SGX_AESGCM_IV_SIZE+len;
	memcpy(encrypted_response, p_dst, *encrypted_response_len);

    return NO_ERROR;
}

int ecall_secure_command(const char* sessionID, int sessionID_len, const char* encrypted_cmd, int encrypted_cmd_len, char* encrypted_response, int* encrypted_response_len) {

    // error index of this ecall function
    int result_error_index;

    // error index of encryption result
    int encryption_result;

    //
    // decrypt cmd
    //

    uint8_t *encMessage = (uint8_t *) encrypted_cmd;
	uint8_t p_dst[BUFLEN] = {0};
    string session_ID = string(sessionID, sessionID_len);
    
    // sgx_aes_gcm_128bit_key_t *session_key = &(state.users[session_ID]->session_key);
    // test code
    sgx_aes_gcm_128bit_key_t skey = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    sgx_aes_gcm_128bit_key_t *session_key = &skey;

    size_t decMessageLen = encrypted_cmd_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;
	sgx_status_t status = sgx_rijndael128GCM_decrypt(
		session_key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		decMessageLen,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE,
        SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage
    );

    if (status != SGX_SUCCESS) {
        // return encrypted response to client
        // make encrypted response 
        // and return NO_ERROR to hide the ecall result from rouTEE host
        encryption_result = make_encrypted_response(ERR_DECRYPT_FAILED, session_key, encrypted_response, encrypted_response_len);
        if (encryption_result != NO_ERROR) {
            return ERR_ENCRYPT_FAILED;
        }
        return NO_ERROR;
    }
    
    char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
	memcpy(decMessage, p_dst, decMessageLen);
    decMessage[decMessageLen] = '\0';
    printf("decrypted cmd: %s\n", decMessage);

    //
    // execute decrypted cmd
    //

    // parse the command to get parameters
    vector<string> params;
    string cmd = string(decMessage, decMessageLen);
    split(cmd, params, ' ');

    // find appropriate operation
    char operation = params[0][0];
    int operation_result;
    if (operation == OP_CREATE_CHANNEL) {
        // add deposit request
        if (params.size() != 3) {
            // invalid parameter count
            operation_result = ERR_INVALID_PARAMS;
        }
        else {
            // get parameters
            string tx_id = params[1];
            unsigned int tx_index = strtoul(params[2].c_str(), NULL, 10);

            // execute operation
            operation_result = secure_create_channel(tx_id.c_str(), tx_id.length(), tx_index);
        }
    }
    else if (operation == OP_SETTLE_BALANCE) {
        // settle balance request
        if (params.size() != 2) {
            // invalid parameter count
            operation_result = ERR_INVALID_PARAMS;
        }
        else {
            // get parameters
            string receiver_address = params[1];

            // execute operation
            operation_result = secure_settle_balance(receiver_address.c_str(), receiver_address.length());
        }
    }
    else if (operation == OP_DO_MULTIHOP_PAYMENT) {
        // multi-hop payment request
        if (params.size() != 5) {
            // invalid parameter count
            operation_result = ERR_INVALID_PARAMS;
        }
        else {
            // get parameters
            string sender_address = params[1];
            string receiver_address = params[2];
            unsigned long long amount = strtoul(params[3].c_str(), NULL, 10);
            unsigned long long fee = strtoul(params[4].c_str(), NULL, 10);

            // execute operation
            operation_result = secure_do_multihop_payment(sender_address.c_str(), sender_address.length(), receiver_address.c_str(), receiver_address.length(), amount, fee);
        }
    }
    else if (operation == OP_UPDATE_LATEST_SPV_BLOCK) {
        // update user's latest SPV block
        if (params.size() != 2) {
            // invalid parameter count
            operation_result = ERR_INVALID_PARAMS;
        }
        else {
            // get parameters
            string user_address = params[1];
            unsigned long long block_number = strtoul(params[2].c_str(), NULL, 10);
            // string block_hash = params[3];

            // execute operation
            operation_result = secure_update_latest_SPV_block(user_address.c_str(), user_address.length(), block_number);
        }
    }
    else {
        // invalid opcode
        operation_result = ERR_INVALID_OP_CODE;
    }

    //
    // encrypt response
    //

    // encrypt the response for client & return NO_ERROR to hide the ecall result from rouTEE host
    encryption_result = make_encrypted_response(operation_result, session_key, encrypted_response, encrypted_response_len);
    if (encryption_result != NO_ERROR) {
        return ERR_ENCRYPT_FAILED;
    }
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
        return ERR_SEAL_FAILED;
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
        return ERR_UNSEAL_FAILED;
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
        return ERR_SEAL_FAILED;
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
        return ERR_UNSEAL_FAILED;
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
