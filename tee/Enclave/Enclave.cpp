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

// bitcoin Pay-to-PubkeyHash tx size info (approximately, tx size = input_num * input_size + output_num * output_size)
#define TX_INPUT_SIZE 150 // bytes
#define TX_OUTPUT_SIZE 40 // bytes

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

// operation function for secure_command
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
    // real implementation for secure_get_ready_for_deposit()
    // 1. params: sender's settlement address
    // 2. return: randomly genereated address to receive deposit from sender & latest block info in rouTEE header chain
    //

}

void ecall_print_state() {
    // print all the state: all users' address and balance
    printf("\n\n\n\n\n\n\n\n\n\n******************** START PRINT STATE ********************\n");

    printf("\n\n\n***** owner info *****\n\n");
    printf("owner address: %s\n", state.owner_address.c_str());

    printf("\n\n\n\n\n***** user account info *****\n\n");
    for (map<string, Account*>::iterator iter = state.users.begin(); iter != state.users.end(); iter++){
        printf("address: %s -> balance: %llu / nonce: %llu / min_requested_block_number: %llu / latest_SPV_block_number: %llu\n", 
            (iter->first).c_str(), iter->second->balance, iter->second->nonce, iter->second->min_requested_block_number, iter->second->latest_SPV_block_number);
    }
    printf("\n=> total %d accounts / total %llu satoshi\n", state.users.size(), state.total_balances);

    printf("\n\n\n\n\n***** deposits *****\n\n");
    int queue_size = state.deposits.size();
    for (int i = 0; i< queue_size; i++) {
        Deposit deposit = state.deposits.front();
        printf("deposit %d: txhash: %s / txindex: %d\n", i, deposit.tx_hash, deposit.tx_index);
        state.deposits.pop();
        state.deposits.push(deposit);
    }

    printf("\n\n\n\n\n***** waiting settle requests *****\n\n");
    queue_size = state.settle_requests_waiting.size();
    for (int i = 0; i < queue_size; i++) {
        SettleRequest sr = state.settle_requests_waiting.front();
        printf("user address: %s / amount: %llu satoshi\n", sr.address, sr.amount);

        // to iterate queue elements
        state.settle_requests_waiting.pop();
        state.settle_requests_waiting.push(sr);
    }

    printf("\n\n\n\n\n***** pending settle requests *****\n\n");
    queue_size = state.pending_settle_tx_infos.size();
    unsigned long long pending_routing_fees = 0;
    for (int i = 0; i < queue_size; i++) {
        PendingSettleTxInfo psti = state.pending_settle_tx_infos.front();
        printf("pending settle tx %d: pending routing fee: %llu satoshi\n", i, psti.pending_routing_fees);
        pending_routing_fees += psti.pending_routing_fees;
        int deposits_size = psti.used_deposits.size();
        for (int j = 0; j < deposits_size; j++) {
            Deposit deposit = psti.used_deposits.front();
            printf("    used deposit %d: txhash: %s / txindex: %d\n", j, deposit.tx_hash, deposit.tx_index);
            psti.used_deposits.pop();
            psti.used_deposits.push(deposit);
        }
        int settle_requests_size = psti.pending_settle_requests.size();
        for (int j = 0; j < settle_requests_size; j++) {
            SettleRequest sr = psti.pending_settle_requests.front();
            printf("    user address: %s / settle amount: %llu satoshi\n", sr.address, sr.amount);

            // to iterate queue elements
            psti.pending_settle_requests.pop();
            psti.pending_settle_requests.push(sr);
        }
        printf("\n");

        // to iterate queue elements
        state.pending_settle_tx_infos.pop();
        state.pending_settle_tx_infos.push(psti);
    }

    printf("\n\n\n\n\n***** routing fees *****\n\n");
    printf("routing fee per payment: %llu satoshi\n", state.routing_fee);
    printf("routing fee address: %s\n", state.fee_address.c_str());
    printf("waiting routing fees: %llu satoshi\n", state.routing_fee_waiting);
    printf("pending routing fees: %llu satoshi\n", pending_routing_fees);
    printf("confirmed routing fees: %llu satoshi\n", state.routing_fee_confirmed);

    printf("\n\n\n******************** END PRINT STATE ********************\n");
    return;
}

// operation function for secure_command
int secure_settle_balance(const char* user_address, int user_addr_len, unsigned long long amount) {
    //
    // TODO: BITCOIN
    // check authority to get paid the balance (ex. user's signature with settlement params)
    // if (no authority to get balance) {
    //     return ERR_NO_AUTHORITY;
    // }
    //

    // check the user has enough balance
    string user_addr = string(user_address, user_addr_len);
    map<string, Account*>::iterator iter = state.users.find(user_addr);
    if (iter == state.users.end() || iter->second->balance < amount) {
        // user is not in the state || has not enough balance
        return ERR_NOT_ENOUGH_BALANCE;
    }
    Account* user_acc = iter->second;

    // push new waiting settle request
    state.settle_requests_waiting.push(SettleRequest());
    state.settle_requests_waiting.back().address = user_addr;
    state.settle_requests_waiting.back().amount = amount;

    // set user's account
    printf("user %s requests settlement: %llu satoshi\n", user_addr.c_str(), amount);
    user_acc->balance -= amount;
    user_acc->nonce++; // prevent payment replay attack    

    // update user's requested_block_number
    if (user_acc->balance == 0) {
        // user settled all balance -> reset min requested block number
        user_acc->min_requested_block_number = 0;
    }

    // update total balances
    state.total_balances -= amount;

    // increase state id
    state.stateID++;

    return NO_ERROR;
}

int ecall_make_settle_transaction(const char* settle_transaction, int* settle_tx_len) {

    // 
    // TODO: check rouTEE is ready to settle
    // ex. check there is no pending settle tx || more than 3 users requested settlement
    //
    if (state.pending_settle_tx_infos.size() != 0 || state.settle_requests_waiting.size() < state.min_settle_users_num) {
        return ERR_SETTLE_NOT_READY;
    }

    // 
    // TODO: BITCOIN
    // ex. unsigned long long routing_fees_to_be_confirmed = make_settle_tx(settle_transaction, settle_tx_len);
    // returns (routing_fees_pending * total_settle_amount / total_balances)
    // and fill in settle_transaction and settle_tx_len
    // and move SettleRequest from state.settle_requests_waiting to state.settle_requests_pending
    // and state.settle_tx_hashes_pending.push(settle_tx_hash)
    // 
    // temp code
    // save infos of this settle tx
    PendingSettleTxInfo psti;
    psti.tx_hash = "0x_settle_tx_hash";
    psti.pending_balances = 0;
    int tx_input_num = state.deposits.size();
    int tx_output_num = state.settle_requests_waiting.size() + 1; // +1 means leftover_deposit
    printf("settle tx intput num: %d / settle tx output num: %d\n", tx_input_num, tx_output_num);
    while(!state.settle_requests_waiting.empty()) {
        SettleRequest sr = state.settle_requests_waiting.front();
        printf("settle tx output: to %s / %llu satoshi\n", sr.address.c_str(), sr.amount);
        psti.pending_balances += sr.amount;

        // change settle requests status: from waiting to pending
        state.settle_requests_waiting.pop();
        psti.pending_settle_requests.push(sr);
    }
    while(!state.deposits.empty()) {
        // move deposits: from unused to used
        Deposit deposit = state.deposits.front();
        state.deposits.pop();
        psti.used_deposits.push(deposit);
    }
    printf("routing fee waiting: %llu / psti.pending balances: %llu / state.total balance: %llu\n", state.routing_fee_waiting, psti.pending_balances, state.total_balances);
    psti.pending_routing_fees = state.routing_fee_waiting * psti.pending_balances / (state.total_balances + psti.pending_balances);
    state.routing_fee_waiting -= psti.pending_routing_fees;
    int settle_tx_size = TX_INPUT_SIZE * tx_input_num + TX_OUTPUT_SIZE * tx_output_num;
    psti.pending_tx_fee = state.avg_tx_fee_per_byte * settle_tx_size;
    state.pending_settle_tx_infos.push(psti);
    state.balances_for_settle_tx_fee -= psti.pending_tx_fee;
    Deposit leftover_deposit;
    state.deposits.push(leftover_deposit);
    psti.leftover_deposit = leftover_deposit;

    return NO_ERROR;
}

// operation function for secure_command
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

    // add routing fee for this payment
    state.routing_fee_waiting += fee;
    // update total balances
    state.total_balances -= fee;

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
int secure_update_latest_SPV_block(const char* user_address, int user_addr_len, unsigned long long block_number) {

    //
    // TODO: BITCOIN
    // check authority to change SPV block
    // ex. verify user's signature
    //

    // check the user exists
    string user_addr = string(user_address, user_addr_len);
    map<string, Account*>::iterator iter = state.users.find(user_addr);
    if (iter == state.users.end()) {
        // the user not exist
        printf("address %s is not in the state\n", user_addr);
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
    else {
        // cannot change to lower block
        return ERR_CANNOT_CHANGE_TO_LOWER_BLOCK;
    }
    
    return NO_ERROR;
}

// this is not ecall function, but this can be used as ecall to debugging
void deal_with_deposit_tx(const char* sender_address, int sender_addr_len, unsigned long long amount, unsigned long long block_number) {

    string sender_addr = string(sender_address, sender_addr_len);

    // check the user exists
    map<string, Account*>::iterator iter = state.users.find(sender_addr);
    if (iter == state.users.end()) {
        // sender is not in the state, create new account
        Account* acc = new Account;
        acc->balance = 0;
        acc->nonce = 0;
        acc->latest_SPV_block_number = 0;
        state.users[sender_addr] = acc;
    }

    // take some of the deposit to pay tx fee later
    unsigned long long balance_for_tx_fee = state.avg_tx_fee_per_byte * TX_INPUT_SIZE;
    state.balances_for_settle_tx_fee += balance_for_tx_fee;

    // update user's balance
    unsigned long long balance_for_user = amount - balance_for_tx_fee;
    state.users[sender_addr]->balance += balance_for_user;

    // update total balances
    state.total_balances += balance_for_user;

    // update user's min_requested_block_number
    if (balance_for_user > 0) {
        state.users[sender_addr]->min_requested_block_number = block_number;
    }

    // add deposit
    Deposit deposit;
    deposit.tx_hash = "some_tx_hash";
    deposit.tx_index = 0;
    deposit.manager_private_key = "0xmanager";
    state.deposits.push(deposit);

    // increase state id
    state.stateID++;
    
    printf("deal with new deposit tx -> user: %s / balance += %llu / tx fee += %llu\n", sender_addr.c_str(), balance_for_user, balance_for_tx_fee);
}

// this is not ecall function, but this can be used as ecall to debugging
void deal_with_settlement_tx() {

    // get this settle tx's info
    // settle txs are included in bitcoin with sequencial order, so just get the first pending settle tx from queue
    PendingSettleTxInfo psti = state.pending_settle_tx_infos.front();
    state.pending_settle_tx_infos.pop();

    // confirm routing fee for this settle tx
    printf("deal with settle tx -> rouTEE owner got paid pending routing fee: %llu satoshi\n", psti.pending_routing_fees);
    state.routing_fee_confirmed += psti.pending_routing_fees;

    // dequeue pending settle requests for this settle tx (print for debugging, can delete this later)
    int queue_size = psti.pending_settle_requests.size();
    for (int i = 0; i < queue_size; i++) {
        SettleRequest sr = psti.pending_settle_requests.front();
        printf("deal with settle tx -> user: %s / settled %llu satoshi\n", sr.address, sr.amount);
        psti.pending_settle_requests.pop();
    }

    // dequeue used deposits for this settle tx (print for debugging, can delete this later)
    queue_size = psti.used_deposits.size();
    for (int i = 0; i < queue_size; i++) {
        Deposit deposit = psti.used_deposits.front();
        printf("deal with settle tx -> used deposit hash: %s\n", deposit.tx_hash);
        psti.used_deposits.pop();
    }

}

int ecall_insert_block(const char* block, int block_len) {
    // 
    // TODO: BITCOIN
    // SPV verify the new bitcoin block
    // verify tx merkle root hash
    // iterate txs to call deal_with_deposit_tx() when find deposit tx
    //             to call deal_with_settlement_tx() when find settlement tx
    // update average tx fee
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

            // execute operation (TODO: should be changed to secure_get_ready_for_deposit() function)
            operation_result = secure_create_channel(tx_id.c_str(), tx_id.length(), tx_index);
        }
    }
    else if (operation == OP_SETTLE_BALANCE) {
        // settle balance request
        if (params.size() != 3) {
            // invalid parameter count
            operation_result = ERR_INVALID_PARAMS;
        }
        else {
            // get parameters
            string receiver_address = params[1];
            unsigned long long amount = strtoul(params[2].c_str(), NULL, 10);

            // execute operation
            operation_result = secure_settle_balance(receiver_address.c_str(), receiver_address.length(), amount);
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
        if (params.size() != 3) {
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
