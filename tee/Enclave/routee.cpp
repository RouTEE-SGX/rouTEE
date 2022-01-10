#include <stdarg.h>
#include <stdio.h>

#include "routee.h"
#include "routee_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "errors.h"
#include "state.h"
#include "utils.h"
#include "network.h"

#include <univalue.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <random.h>
#include "rpc.h"
#include "core_io.h"
#include "pow.h"
#include "chain.h"
#include "consensus/merkle.h"

#include "mbedtls/sha256.h"
#include "bitcoin/key.h"

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include "mbedtls/pem.h"
#include "mbedtls/ctr_drbg.h"

#include <stdlib.h>
#include <string.h>



// print ecall results on screen or not
const bool doPrint = true;
const bool doSealPubkey = false;

// for AES-GCM128 encription / decription
#define SGX_AESGCM_MAC_SIZE 16 // bytes
#define SGX_AESGCM_IV_SIZE 12 // bytes
#define BUFLEN 2048

// bitcoin Pay-to-PubkeyHash tx size info (approximately, tx size = input_num * input_size + output_num * output_size)
#define TX_INPUT_SIZE 150 // bytes
#define TX_OUTPUT_SIZE 40 // bytes

// tax rate to make settle tx (1.1 means 10%)
#define TAX_RATE_FOR_SETTLE_TX 1.1

#include <sgx_thread.h>
sgx_thread_mutex_t state_mutex = SGX_THREAD_MUTEX_INITIALIZER;

#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE

// global state
State state;

// Globals for rouTEE enclave
bool testnet = false;
bool regtest = true;
bool debug = false;
bool benchmark = false;

const CChainParams& chainparams = testnet? Params(CBaseChainParams::TESTNET) : (regtest? Params(CBaseChainParams::REGTEST) : Params(CBaseChainParams::MAIN));
const CBlock& genesis = chainparams.GenesisBlock();
CBlockIndex* lastIndex = new CBlockIndex(genesis.GetBlockHeader());

// invoke OCall to display the enclave buffer to the terminal screen
void printf(const char* fmt, ...) {

    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf); // OCall
}

int ecall_set_routing_fee(const char* command, int cmd_len, const char* signature, int sig_len){

    // verify host's signature
    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, state.host_public_key.c_str(), SGX_RSA3072_KEY_SIZE);
    rsa_pubkey.exp[0] = 1;
    rsa_pubkey.exp[1] = 0;
    rsa_pubkey.exp[2] = 1;
    rsa_pubkey.exp[3] = 0;
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((uint8_t*) cmd_tmp, cmd_len, &rsa_pubkey, (sgx_rsa3072_signature_t*) signature, &result);
    if (result != SGX_RSA_VALID) {
        printf("Signature verification failed\n");
        return ERR_VERIFY_SIG_FAILED;
    }

    // get params from command
    char* _cmd = strtok((char*) command, " ");
    
    char* routing_fee = strtok(NULL, " ");
    if (routing_fee == NULL) {
        printf("No parameter for routing fee\n");
        return ERR_INVALID_PARAMS;
    }

    // set routing fee
    state.min_routing_fee = strtoull(routing_fee, NULL, 10);
    
    // print result
    if (doPrint) {
        printf("set routing fee as %llu satoshi\n", state.min_routing_fee);
    }

    return NO_ERROR;
}

int ecall_set_routing_fee_address(const char* command, int cmd_len, const char* signature, int sig_len){
    
    // verify host's signature
    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, state.host_public_key.c_str(), SGX_RSA3072_KEY_SIZE);
    rsa_pubkey.exp[0] = 1;
    rsa_pubkey.exp[1] = 0;
    rsa_pubkey.exp[2] = 1;
    rsa_pubkey.exp[3] = 0;
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((uint8_t*) cmd_tmp, cmd_len, &rsa_pubkey, (sgx_rsa3072_signature_t*) signature, &result);
    if (result != SGX_RSA_VALID) {
        printf("Signature verification failed\n");
        return ERR_VERIFY_SIG_FAILED;
    }

    // get params from command
    char* _cmd = strtok((char*) command, " ");

    char* _fee_address = strtok(NULL, " ");
    if (_fee_address == NULL) {
        printf("No parameter for routing fee address\n");
        return ERR_INVALID_PARAMS;
    }
    string fee_address = string(_fee_address, BITCOIN_ADDRESS_LEN);

    // check if this is a valid bitcoin address
    if (!CBitcoinAddress(fee_address).IsValid()) {
        return ERR_INVALID_PARAMS;
    }

    // set routing fee address
    state.fee_address = fee_address;

    // print result
    if (doPrint) {
        printf("set routing fee address as %s\n", state.fee_address.c_str());
    }

    return NO_ERROR;
}

// TODO: update this (settle request has fee field)
int ecall_settle_routing_fee(const char* command, int cmd_len, const char* signature, int sig_len) {

    // verify host's signature
    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, state.host_public_key.c_str(), SGX_RSA3072_KEY_SIZE);
    rsa_pubkey.exp[0] = 1;
    rsa_pubkey.exp[1] = 0;
    rsa_pubkey.exp[2] = 1;
    rsa_pubkey.exp[3] = 0;
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((uint8_t*) cmd_tmp, cmd_len, &rsa_pubkey, (sgx_rsa3072_signature_t*) signature, &result);
    if (result != SGX_RSA_VALID) {
        printf("Signature verification failed\n");
        return ERR_VERIFY_SIG_FAILED;
    }

    // get params from command
    char* _cmd = strtok((char*) command, " ");
    
    char* _amount = strtok(NULL, " ");
    if (_amount == NULL) {
        printf("No parameter for settle amount\n");
        return ERR_INVALID_PARAMS;
    }
    unsigned long long amount = strtoull(_amount, NULL, 10);
    
    // amount should be bigger than minimum settle amount
    // minimum settle amount = tax to make settlement tx with only 1 settle request user = maximum tax to make settle tx
    unsigned long long minimun_settle_amount = (TX_INPUT_SIZE + TX_OUTPUT_SIZE) * state.avg_tx_fee_per_byte * TAX_RATE_FOR_SETTLE_TX;
    if (amount <= minimun_settle_amount) {
        printf("too low amount -> minimun_settle_amount: %llu\n", minimun_settle_amount);
        return ERR_TOO_LOW_SETTLE_FEE;
    }

    // check there is enough confirmed routing fee to settle
    if (amount > state.confirmed_routing_fee) {
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // push new waiting settle request
    SettleRequest* sr = new SettleRequest;
    // sr->user_address = "host"
    sr->settle_address = state.fee_address;
    sr->amount = amount;
    state.settle_requests.push(*sr);

    // update host's routing fees
    state.confirmed_routing_fee -= amount;
    state.d_settled_routing_fee += amount;

    // increase state id
    state.stateID++;

    // print result
    if (doPrint) {
        printf("host %s requests settlement: %llu satoshi\n", state.fee_address.c_str(), amount);
    }

    return NO_ERROR;
}

void ecall_print_state() {
    // print all the state: all users' address and balance
    printf("\n\n\n\n\n\n\n\n\n\n******************** START PRINT STATE ********************\n");

    printf("\n\n\n\n\n***** user account info *****\n\n");
    if (state.users.size() <=  10){
        for (int i = 0; i < state.users.size(); i++) {
            printf("user index: %d -> balance: %llu / nonce: %llu / min_requested_block_number: %llu / latest_SPV_block_number: %llu\n",
                i, state.users[i].balance, state.users[i].nonce, state.users[i].min_requested_block_number, state.users[i].latest_SPV_block_number);
        }
    }
    printf("\n=> total %d accounts / total %llu satoshi\n", state.users.size(), state.total_balances);

    printf("\n\n\n\n\n***** deposit requests *****\n\n");
    for (map<string, DepositRequest*>::iterator iter = state.deposit_requests.begin(); iter != state.deposit_requests.end(); iter++){
        printf("manager key id: %s -> beneficiary index: %d / manager address: %s / block number:%llu\n", 
            (iter->first).c_str(), iter->second->beneficiary_index, iter->second->manager_private_key.c_str(), iter->second->block_number);
    }

    printf("\n\n\n\n\n***** deposits *****\n\n");
    int queue_size = state.deposits.size();
    for (int i = 0; i< queue_size; i++) {
        Deposit* deposit = state.deposits.front();
        printf("deposit %d: txhash: %s / txindex: %d\n", i, deposit->tx_hash.c_str(), deposit->tx_index);
        state.deposits.pop();
        state.deposits.push(deposit);
    }

    printf("\n\n\n\n\n***** waiting settle requests *****\n\n");
    queue_size = state.settle_requests.size();
    queue<SettleRequest> temp_settle_requests;
    for (int i = 0; i < queue_size; i++) {
        SettleRequest sr = state.settle_requests.top();
        printf("user index: %d / amount: %llu satoshi / fee: %llu \n", sr.user_index, sr.amount, sr.fee);
        state.settle_requests.pop();
        temp_settle_requests.push(sr);
    }
    for (int i = 0; i < queue_size; i++) {
        SettleRequest sr = temp_settle_requests.front();
        temp_settle_requests.pop();
        state.settle_requests.push(sr);
    }

    printf("\n\n\n\n\n***** pending settle requests *****\n\n");
    queue_size = state.pending_settle_tx_infos.size();
    unsigned long long to_be_confirmed_routing_fee = 0;
    for (int i = 0; i < queue_size; i++) {
        PendingSettleTxInfo* psti = state.pending_settle_tx_infos.front();
        printf("pending settle tx %d: pending routing fee: %llu satoshi\n", i, psti->to_be_confirmed_routing_fee);
        to_be_confirmed_routing_fee += psti->to_be_confirmed_routing_fee;
        int deposits_size = psti->used_deposits.size();
        for (int j = 0; j < deposits_size; j++) {
            Deposit* deposit = psti->used_deposits.front();
            printf("    used deposit %d: txhash: %s / txindex: %d\n", j, deposit->tx_hash.c_str(), deposit->tx_index);
            psti->used_deposits.pop();
            psti->used_deposits.push(deposit);
        }
        int settle_requests_size = psti->pending_settle_requests.size();
        for (int j = 0; j < settle_requests_size; j++) {
            SettleRequest* sr = psti->pending_settle_requests.front();
            printf("    user index: %d / settle amount: %llu satoshi\n", sr->user_index, sr->amount);

            // to iterate queue elements
            psti->pending_settle_requests.pop();
            psti->pending_settle_requests.push(sr);
        }
        printf("\n");

        // to iterate queue elements
        state.pending_settle_tx_infos.pop();
        state.pending_settle_tx_infos.push(psti);
    }

    printf("\n\n\n\n\n***** routing fees *****\n\n");
    printf("routing fee per payment: %llu satoshi\n", state.min_routing_fee);
    printf("routing fee address: %s\n", state.fee_address.c_str());
    printf("pending routing fees: %llu satoshi\n", state.pending_routing_fee);
    printf("to be confirmed routing fees: %llu satoshi\n", to_be_confirmed_routing_fee);
    printf("confirmed routing fees: %llu satoshi\n", state.confirmed_routing_fee);
    printf("settled routing fees = %llu\n", state.d_settled_routing_fee);

    printf("\n\n\n\n\n***** check correctness *****\n\n");
    bool isCorrect = true;
    printf("d_total_deposit = %llu\n\n", state.d_total_deposit);
    printf("total_balances = %llu\n", state.total_balances);
    printf("d_total_settle_amount = %llu\n", state.d_total_settle_amount);
    printf("d_total_balances_for_settle_tx_fee = %llu\n", state.d_total_balances_for_settle_tx_fee);
    printf("pending_routing_fee = %llu\n", state.pending_routing_fee);
    printf("to_be_confirmed_routing_fee = %llu\n", to_be_confirmed_routing_fee);
    printf("confirmed_routing_fee = %llu\n", state.confirmed_routing_fee);
    printf("d_settled_routing_fee = %llu\n", state.d_settled_routing_fee);
    printf("current block number = %llu\n", state.latest_block_number);

    unsigned long long calculated_total_deposit = 0;
    calculated_total_deposit += state.total_balances;
    calculated_total_deposit += state.d_total_settle_amount;
    calculated_total_deposit += state.d_total_balances_for_settle_tx_fee;
    calculated_total_deposit += state.pending_routing_fee;
    calculated_total_deposit += to_be_confirmed_routing_fee;
    calculated_total_deposit += state.confirmed_routing_fee;
    calculated_total_deposit += state.d_settled_routing_fee;
    if (state.d_total_deposit != calculated_total_deposit) {
        printf("\n=> ERROR: total deposit is not correct, some balances are missed\n\n");
        isCorrect = false;
    }
    printf("\n");

    printf("d_total_balances_for_settle_tx_fee = %llu\n\n", state.d_total_balances_for_settle_tx_fee);
    printf("balances_for_settle_tx_fee = %llu\n", state.fee_fund);
    printf("d_total_settle_tx_fee = %llu\n", state.d_total_settle_tx_fee);
    unsigned long long calculated_total_balances_for_settle_tx_fee = 0;
    calculated_total_balances_for_settle_tx_fee += state.fee_fund;
    calculated_total_balances_for_settle_tx_fee += state.d_total_settle_tx_fee;
    if (state.d_total_balances_for_settle_tx_fee != calculated_total_balances_for_settle_tx_fee) {
        printf("\n=> ERROR: total balance for settle tx fee is not correct, some balances are missed\n\n");
        isCorrect = false;
    }
    if (isCorrect) {
        printf("\n=> CORRECT: all deposits are in correct way\n\n");
    }
    printf("\n\n\n******************** END PRINT STATE ********************\n");
    return;
}

// ADD_USER(user_address, settle_address, public_key) operation
int secure_add_user(const char* command, int cmd_len, const char* public_key, const char* response_msg) {

    // get params from command
    char* _cmd = strtok((char*) command, " ");

    char* _user_address = strtok(NULL, " ");
    if (_user_address == NULL) {
        printf("No sender address\n");
        return ERR_INVALID_PARAMS;
    }

    char* _settle_address = strtok(NULL, " ");
    if (_settle_address == NULL) {
        printf("No settle address\n");
        return ERR_INVALID_PARAMS;
    }

    // check if this is a valid bitcoin address
    string user_address(_user_address, BITCOIN_ADDRESS_LEN);
    if (!CBitcoinAddress(user_address).IsValid()) {
        printf("Invalid sender address\n");
        return ERR_INVALID_PARAMS;
    }

    // check if this is a valid bitcoin address
    string settle_address(_settle_address, BITCOIN_ADDRESS_LEN);
    if (!CBitcoinAddress(settle_address).IsValid()) {
        printf("Invalid settle address\n");
        return ERR_INVALID_PARAMS;
    }

    // sgx_thread_mutex_lock(&state_mutex);

    // create new account for the user
    Account acc;
    acc.balance = 0;
    acc.balance = 10000000; // test code, delete this later
    state.total_balances += 10000000; // test code, delete this later
    acc.nonce = 0;
    acc.min_requested_block_number = 0;
    acc.latest_SPV_block_number = 0;
    memcpy(acc.settle_address, settle_address.c_str(), BITCOIN_ADDRESS_LEN);
    memcpy(acc.public_key, public_key, RSA_PUBLIC_KEY_LEN);
    state.users.push_back(acc);
    
    // print result
    if (doPrint) {
        printf("ADD_USER success: user index: %d / settle address: %s\n", state.users.size()-1, settle_address.c_str());
    }

    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// ADD_DEPOSIT(beneficiary_index) operation
int secure_get_ready_for_deposit(const char* command, int cmd_len, const char* response_msg) {

    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");
    char* _beneficiary_index = strtok(NULL, " ");
    if (_beneficiary_index == NULL) {
        printf("No sender index\n");
        return ERR_INVALID_PARAMS;
    }

    // check if the user exists
    int beneficiary_index = atoi(_beneficiary_index);
    if (beneficiary_index > state.users.size()) {
        printf("No sender account exist in rouTEE\n");
        return ERR_NO_USER_ACCOUNT;
    }

    // sgx_thread_mutex_lock(&state_mutex);

    // randomly generate a bitcoin address to be paid by the user (manager address)
    CKey key;
    key.MakeNewKey(true /* compressed */);
    CPubKey pubkey = key.GetPubKey();
    CKeyID keyid = pubkey.GetID();
    CBitcoinAddress address;
    address.Set(keyid);

    std::string manager_address = address.ToString();
    std::string manager_public_key = HexStr(pubkey);
    std::string manager_private_key = CBitcoinSecret(key).ToString();

    // printf("prikey: %s\n", manager_private_key.c_str());
    // printf("pubkey: %s\n", manager_public_key.c_str());
    // printf("keyid: %s\n", HexStr(keyid).c_str());
    // printf("address: %s\n",manager_address.c_str());

    // add to pending deposit list
    DepositRequest *deposit_request = new DepositRequest;
    deposit_request->manager_private_key = manager_private_key;
    deposit_request->beneficiary_index = beneficiary_index;
    deposit_request->block_number = state.latest_block_number;
    state.deposit_requests[HexStr(keyid)] = deposit_request; // keyid string should be HexStr(keyid), not keyid.ToString()
    
    // print result
    if (doPrint) {
        printf("ADD_DEPOSIT success: random manager address: %s / block number: %llu\n", manager_address.c_str(), state.latest_block_number);
    }

    // return manager address to the sender
    memcpy((char*)response_msg, manager_address.c_str(), manager_address.length()+1);

    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// UPDATE_BOUNDARY_BLOCK(user_index block_number block_hash signature) operation
int secure_update_latest_SPV_block(const char* command, int cmd_len, const char* signature, const char* response_msg) {

    // temply save before getting params for verifying signature later
    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");
    char* _user_index = strtok(NULL, " ");
    if (_user_index == NULL) {
        printf("No user index for update last SPV block\n");
        return ERR_INVALID_PARAMS;
    }

    char* _block_number = strtok(NULL, " ");
    if (_block_number == NULL) {
        printf("No block number for update last SPV block\n");
        return ERR_INVALID_PARAMS;
    }

    char* _block_hash = strtok(NULL, " ");
    if (_block_hash == NULL) {
        printf("No block hash for update last SPV block\n");
        return ERR_INVALID_PARAMS;
    }  

    int user_index = atoi(_user_index);
    unsigned long long block_number = strtoull(_block_number, NULL, 10);
    string block_hash_str(_block_hash, BITCOIN_HEADER_HASH_LEN*2);
    uint256 block_hash;
    block_hash.SetHex(string(block_hash_str, BITCOIN_HEADER_HASH_LEN));

    // check if this is a valid user index
    if (user_index > state.users.size()) {
        printf("Invalid user index for update last SPV block\n");
        return ERR_INVALID_PARAMS;
    }

    if (block_number > state.latest_block_number) {
        printf("Given block number is higher than rouTEE has\n");
        return ERR_INVALID_PARAMS;
    }

    // check user has same block with rouTEE
    if (state.block_hashes[block_number - state.start_block_number] != block_hash) {
        printf("Given block hash is different from rouTEE has\n");
        return ERR_INVALID_PARAMS;
    }

    Account* user_acc = &state.users[user_index];

    // verify signature
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, user_acc->public_key, SGX_RSA3072_KEY_SIZE);
    rsa_pubkey.exp[0] = 1;
    rsa_pubkey.exp[1] = 0;
    rsa_pubkey.exp[2] = 1;
    rsa_pubkey.exp[3] = 0;
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((uint8_t*) cmd_tmp, cmd_len, &rsa_pubkey, (sgx_rsa3072_signature_t*) signature, &result);
    if (result != SGX_RSA_VALID) {
        printf("Signature verification failed\n");
        return ERR_VERIFY_SIG_FAILED;
    }

    // sgx_thread_mutex_lock(&state_mutex);

    // update boundary block to newer one
    if (user_acc->latest_SPV_block_number >= block_number) {
        // cannot change boundary block to lower block
        return ERR_CANNOT_CHANGE_TO_LOWER_BLOCK;
    }
    user_acc->latest_SPV_block_number = block_number;

    // print result
    if (doPrint) {
        printf("UPDATE_BOUNDARY_BLOCK success: user %d update boundary block number to %llu\n", user_index, block_number);
    }
    
    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// MULTI-HOP_PAYMENT(sender_index batch_size [receiver_index amount]*batch_size fee signature) operation
int secure_do_multihop_payment(const char* command, int cmd_len, const char* signature, const char* response_msg) {

    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");

    char* _sender_index = strtok(NULL, " ");
    if (_sender_index == NULL) {
        printf("No sender index for multihop payment\n");
        return ERR_INVALID_PARAMS;
    }

    char* _batch_size = strtok(NULL, " ");
    if (_batch_size == NULL) {
        printf("No batch size for multihop payment\n");
        return ERR_INVALID_PARAMS;
    }

    int sender_index = atoi(_sender_index);
    int batch_size = atoi(_batch_size);

    // check if this is a valid user index
    if (sender_index > state.users.size()) {
        printf("Invalid user index for update boundary block\n");
        return ERR_INVALID_PARAMS;
    }
    Account* sender_acc = &state.users[sender_index];

    queue<PaymentInfo> queue;
    Account* receiver_acc;
    int receiver_index;
    unsigned long long amount;
    unsigned long long total_amount = 0;
    unsigned long long sender_max_source_block_number = sender_acc->min_requested_block_number;

    for (int i = 0; i < batch_size; i++) {

        // get params from command
        char* _receiver_index = strtok(NULL, " ");
        if (_receiver_index == NULL) {
            printf("No receiver address for multihop payment\n");
            return ERR_INVALID_PARAMS;
        }

        char* _amount = strtok(NULL, " ");
        if (_amount == NULL) {
            printf("No amount parameter for multihop payment\n");
            return ERR_INVALID_PARAMS;
        }

        receiver_index = atoi(_receiver_index);
        amount = strtoull(_amount, NULL, 10);

        // check the receiver exists
        if (receiver_index > state.users.size()) {
            printf("Invalid user index for update last SPV block\n");
            return ERR_INVALID_PARAMS;
        }

        // check if the receiver is ready to get paid (temporarily deprecated for easy tests) (for debugging)
        if (sender_acc->min_requested_block_number > state.users[receiver_index].latest_SPV_block_number) {
            return ERR_RECEIVER_NOT_READY;
        }

        total_amount += amount;
        queue.push(PaymentInfo(receiver_index, amount, sender_max_source_block_number));
    }

    if (batch_size != queue.size()) {
        printf("Batch size is different from queue size\n");
        return ERR_INVALID_PARAMS;
    }

    // get params from command
    char* _fee = strtok(NULL, " ");
    if (_fee == NULL) {
        printf("No routing fee parameter for multihop payment\n");
        return ERR_INVALID_PARAMS;
    }
    unsigned long long fee = strtoull(_fee, NULL, 10);

    // check if routing fee is enough
    if (fee < state.min_routing_fee) {
        return ERR_NOT_ENOUGH_FEE;
    }

    // check if the sender can afford this payments
    if (sender_acc->balance < total_amount + batch_size * fee) {
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // verify signature
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, sender_acc->public_key, SGX_RSA3072_KEY_SIZE);
    rsa_pubkey.exp[0] = 1;
    rsa_pubkey.exp[1] = 0;
    rsa_pubkey.exp[2] = 1;
    rsa_pubkey.exp[3] = 0;
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((uint8_t*) cmd_tmp, cmd_len, &rsa_pubkey, (sgx_rsa3072_signature_t*) signature, &result);
    if (result != SGX_RSA_VALID) {
        printf("Signature verification failed\n");
        return ERR_VERIFY_SIG_FAILED;
    }

    // sgx_thread_mutex_lock(&state_mutex);

    // collect payment requests
    for (int i = 0; i < batch_size; i++) {
        PaymentInfo payment_info = queue.front();
        state.payments.push_back(payment_info);
        queue.pop();

        // reduce sender's balance
        sender_acc->balance -= (payment_info.amount + fee);
    }

    // add routing fee for this payment
    state.pending_routing_fee_in_round += batch_size*fee;
    
    // update total balances
    state.total_balances -= batch_size*fee;

    // increase sender's nonce
    sender_acc->nonce++;

    // reset sender's max source block number if balances becomes 0
    if (sender_acc->balance == 0) {
        sender_acc->min_requested_block_number = 0;
    }

    // increase state id
    state.stateID++;

    // print result
    if (doPrint) {
        printf("PAYMENT success: user %d send %llu satoshi to user %d (routing fee: %llu)\n", sender_index, amount, receiver_index, fee);
    }

    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// TODO: add "fee" param in command & refactoring ecall_make_settle_transaction() function
// SETTLEMENT(user_index amount (fee) signature) operation: make settle request for user balance
int secure_settle_balance(const char* command, int cmd_len, const char* signature, const char* response_msg) {

    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");

    char* _user_index = strtok(NULL, " ");
    if (_user_index == NULL) {
        printf("No user index for settle balance\n");
        return ERR_INVALID_PARAMS;
    }
    
    char* _amount = strtok(NULL, " ");
    if (_amount == NULL) {
        printf("No amount parameter for settle balance\n");
        return ERR_INVALID_PARAMS;
    }

    char* _fee = strtok(NULL, " ");
    if (_fee == NULL) {
        printf("No fee parameter for settle balance\n");
        return ERR_INVALID_PARAMS;
    }

    int user_index = atoi(_user_index);
    unsigned long long amount = strtoull(_amount, NULL, 10);
    unsigned long long fee = strtoull(_fee, NULL, 10);
    
    // check if the user exists
    if (user_index > state.users.size()) {
        printf("No user index exist in rouTEE\n");
        return ERR_NO_USER_ACCOUNT;
    }
    Account* user_acc = &state.users[user_index];

    // verify signature
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, user_acc->public_key, SGX_RSA3072_KEY_SIZE);
    rsa_pubkey.exp[0] = 1;
    rsa_pubkey.exp[1] = 0;
    rsa_pubkey.exp[2] = 1;
    rsa_pubkey.exp[3] = 0;
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((uint8_t*) cmd_tmp, cmd_len, &rsa_pubkey, (sgx_rsa3072_signature_t*) signature, &result);
    if (result != SGX_RSA_VALID) {
        printf("Signature verification failed\n");
        return ERR_VERIFY_SIG_FAILED;
    }

    // the user should pay for more than one on-chain tx output
    unsigned long long min_fee = TX_OUTPUT_SIZE * state.avg_tx_fee_per_byte;
    if (fee < min_fee) {
        printf("too low settle fee -> minimum settle fee: %llu\n", min_fee);
        return ERR_TOO_LOW_SETTLE_FEE;
    }

    // check the user has enough balance
    if (user_acc->balance < amount + fee) {
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // sgx_thread_mutex_lock(&state_mutex);

    // push new waiting settle request
    SettleRequest* sr = new SettleRequest;
    sr->user_index = user_index;
    sr->settle_address = string(user_acc->settle_address, BITCOIN_ADDRESS_LEN);
    sr->amount = amount;
    sr->fee = fee;
    state.collected_settle_fees += fee;
    state.settle_requests.push(*sr);

    // set user's account
    user_acc->balance -= amount + fee;
    user_acc->nonce++; // prevent payment replay attack    

    // reset user's max source block number if balance becomes 0
    if (user_acc->balance == 0) {
        user_acc->min_requested_block_number = 0;
    }

    // update total balances
    state.total_balances -= amount + fee;

    // increase state id
    state.stateID++;

    // for debugging
    state.d_total_settle_amount += amount + fee;

    // print result
    if (doPrint) {
        printf("SETTLEMENT success: user index: %d / amount: %llu / fee: %llu\n", user_index, amount, fee);
    }

    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

std::string create_raw_transaction_rpc() {
    std::string create_transaction_rpc = "";
    if (testnet) {
        create_transaction_rpc += "-testnet ";
    }
    else if (regtest) {
        create_transaction_rpc += "-regtest ";
    }
    create_transaction_rpc += "createrawtransaction ";
    return create_transaction_rpc;
}

std::string sign_raw_transaction_rpc() {
    std::string sign_transaction_rpc = "";
    if (testnet) {
        sign_transaction_rpc += "-testnet ";
    }
    else if (regtest) {
        sign_transaction_rpc += "-regtest ";
    }
    sign_transaction_rpc += "signrawtransaction ";
    return sign_transaction_rpc;
}

// generate an on-chain settlement transaction
int ecall_make_settle_transaction(const char* settle_transaction_ret, int* settle_tx_len) {

    // check rouTEE is ready to settle
    // ex. check there is no pending settle tx || at least 1 user requested settlement
    if (state.pending_settle_tx_infos.size() != 0 || state.settle_requests.size() == 0) {
        return ERR_SETTLE_NOT_READY;
    }

    // check if settlement tx can be made without leftover deposit
    bool hasLeftoverDeposit = (state.total_balances + state.pending_routing_fee + state.confirmed_routing_fee != 0);
    if (!hasLeftoverDeposit) {
        // quite rare case, RouTEE will become empty
        printf("there is nothing left to settle. this settle tx cleans all the things.\n");
        //
        // TODO: implement GenerateCleanUpTransaction()
        //
        // settle_tx = GenerateCleanUpTransaction();
        return NO_ERROR;
    }

    // get number of input & output of settlement tx with leftover deposit
    int tx_input_num = state.deposits.size();
    int tx_output_num = state.settle_requests.size() + 1;

    // check if we can afford on-chain settlement transaction fee
    int tx_size = TX_INPUT_SIZE * tx_input_num + TX_OUTPUT_SIZE * tx_output_num + 10;
    unsigned long long tx_fee = tx_size * state.avg_tx_fee_per_byte;
    unsigned long long accumulated_tx_fees = state.fee_fund + state.collected_settle_fees - TX_INPUT_SIZE * state.avg_tx_fee_per_byte;
    queue<SettleRequest> temp_settle_requests; // buffer for droped out requests;
    while(tx_fee > accumulated_tx_fees) {
        // drop out settle request with lowest settle fee
        SettleRequest sr = state.settle_requests.top();
        state.settle_requests.pop();
        temp_settle_requests.push(sr);

        // check the condition again
        tx_output_num--;
        if (tx_output_num == 1) {
            // not enough settle fees, cannot make proper on-chain tx, just re-push requests
            int queue_size = temp_settle_requests.size();
            for (int i = 0; i < queue_size; i++) {
                SettleRequest sr = temp_settle_requests.front();
                state.settle_requests.push(sr);
                temp_settle_requests.pop();
            }
            return ERR_TOO_LOW_SETTLE_FEE;
        }
        tx_size -= TX_OUTPUT_SIZE;
        tx_fee = tx_size * state.avg_tx_fee_per_byte;
        accumulated_tx_fees -= sr.fee;
    }

    // save infos of this settle tx
    PendingSettleTxInfo* psti = new PendingSettleTxInfo;

    // make transaction inputs for settle transaction
    string input_string = "[";
    string prevouts = "[";
    string privkey = "[";

    while (!state.deposits.empty()) {
        // move deposits: from unused to used
        Deposit* deposit = state.deposits.front();
        state.deposits.pop();

        string tx_hash = deposit->tx_hash;
        unsigned long long tx_index = deposit->tx_index;
        string script = deposit->script;

        input_string += "{\"txid\":\"" + tx_hash + "\",\"vout\":" + long_long_to_string(0) + "}";
        prevouts += "{\"txid\":\"" + tx_hash + "\",\"vout\":" + long_long_to_string(0) + ",\"scriptPubKey\":\"" + script + "\",\"redeemScript\":\"\"}";
        privkey += "\"" + deposit->manager_private_key + "\"";
        if (!state.deposits.empty()) {
            input_string += ","; // add commas if not last item
            prevouts += ",";
            privkey += ",";
        }
        else {
            input_string += "]"; // add bracket if last item
            prevouts += "]";
            privkey += "]";
        }
        psti->used_deposits.push(deposit);
    }
    
    // make transaction outputs for settle transaction
    string output_string = "{";
    unsigned total_settle_amount = 0;

    while(!state.settle_requests.empty()) {
        SettleRequest sr = state.settle_requests.top();
        state.settle_requests.pop();
        psti->pending_balances += sr.amount;
        if (doPrint) {
            printf("settle tx output: to %s / %llu satoshi\n", sr.settle_address.c_str(), sr.amount);
        }

        // change settle requests status: from waiting to pending
        // & calculate settlement tax
        state.fee_fund += sr.fee;
        state.collected_settle_fees -= sr.fee;
        state.d_total_balances_for_settle_tx_fee += sr.fee;
        state.d_total_settle_amount -= sr.fee;

        output_string += "\"" + sr.settle_address + "\":" + satoshi_to_bitcoin(sr.amount) + ",";
        total_settle_amount += sr.amount;

        if (state.settle_requests.empty()) {
            // generate random manager address for leftover deposit
            CKey key;
            key.MakeNewKey(true /* compressed */);
            CPubKey pubkey = key.GetPubKey();
            CKeyID keyid = pubkey.GetID();
            CBitcoinAddress address;
            address.Set(keyid);

            std::string manager_address = address.ToString();
            std::string manager_public_key = HexStr(pubkey);
            std::string manager_private_key = CBitcoinSecret(key).ToString();

            // generate leftover deposit
            Deposit* leftover_deposit = new Deposit;
            leftover_deposit->tx_index = tx_output_num - 1;
            CScript scriptPubKey = GetScriptForDestination(address.Get());
            leftover_deposit->script = HexStr(scriptPubKey); // TODO: is this right?
            leftover_deposit->manager_private_key = manager_private_key;

            unsigned long long total_out = state.d_total_deposit - total_settle_amount - ((tx_output_num * TX_OUTPUT_SIZE) + TX_INPUT_SIZE) * state.avg_tx_fee_per_byte;

            output_string += "\"" + manager_address + "\":" + satoshi_to_bitcoin(total_out) + "}";

            state.deposits.push(leftover_deposit);
            psti->leftover_deposit = leftover_deposit;
            // printf("state.d_total_deposit: %llu, total_settle_amount: %llu, total_out: %llu\n", state.d_total_deposit, total_settle_amount, total_out);
        }
        psti->pending_settle_requests.push(&sr);
    }

    // amount of pending routing fees to be confirmed
    psti->to_be_confirmed_routing_fee = state.pending_routing_fee * psti->pending_balances / (state.total_balances + psti->pending_balances);
    state.pending_routing_fee -= psti->to_be_confirmed_routing_fee;

    // measure on-chain tx fee
    psti->on_chain_tx_fee = tx_size * state.avg_tx_fee_per_byte;
    state.fee_fund -= psti->on_chain_tx_fee;

    // save this on-chain settle tx information
    state.pending_settle_tx_infos.push(psti);
    
    // for debugging
    state.d_total_settle_tx_fee += psti->on_chain_tx_fee;

    // print result
    if (doPrint) {
        printf("input string: %s\n", input_string.c_str());
        printf("output string: %s\n", output_string.c_str());
        printf("settle tx intput num: %d / settle tx output num: %d\n", tx_input_num, tx_output_num);
        printf("routing fee waiting: %llu / psti->pending balances: %llu / state.total balance: %llu\n", state.pending_routing_fee, psti->pending_balances, state.total_balances);
    }

    // generate on-chain transaction
    // printf("input string: %s\noutput string: %s\n", input_string.c_str(), output_string.c_str());
    std::string create_transaction_rpc = create_raw_transaction_rpc();
    create_transaction_rpc += input_string + " " + output_string;
    // printf("create transaction rpc: %s\n", create_transaction_rpc.c_str());
    UniValue settle_transaction = executeCommand(create_transaction_rpc);
    std::string settle_transaction_string = settle_transaction.write();
    // printf("settle_transaction_string: %s\n", settle_transaction_string.c_str());

    std::string sign_transaction_rpc = sign_raw_transaction_rpc();
    sign_transaction_rpc += settle_transaction_string.substr(1, settle_transaction_string.size() - 2) + " " + prevouts + " " + privkey + " ALL";
    // printf("sign_transaction_rpc: %s\n", sign_transaction_rpc.c_str());
    UniValue signed_settle_transaction = executeCommand(sign_transaction_rpc);
    std::string signed_settle_transaction_string = signed_settle_transaction.write();
    // printf("signed_settle_transaction_string: %s\n", signed_settle_transaction_string.c_str());

    psti->leftover_deposit->tx_hash = signed_settle_transaction["txid"].get_str(); // TODO: is it right?

    *settle_tx_len = signed_settle_transaction_string.length();
    memcpy((char*) settle_transaction_ret, signed_settle_transaction_string.c_str(), signed_settle_transaction_string.length());

    return NO_ERROR;
}

// TODO: deals with accumulated requests & backup important data
int ecall_process_round(const char* settle_transaction_ret, int* settle_tx_len, char* sealed_state, int* sealed_state_len) {
    
    //
    // TODO: verify host's signature
    //

    // mutex lock
    sgx_thread_mutex_lock(&state_mutex);

    //
    // 1. deals with payments
    //

    // deals with receivers
    for (auto pi = state.payments.begin(); pi != state.payments.end(); ++pi) {
        state.users[pi->receiver_index].balance += pi->amount;
        if (state.users[pi->receiver_index].min_requested_block_number < pi->source_block_number) {
            state.users[pi->receiver_index].min_requested_block_number = pi->source_block_number;
        }
        // printf("PAYMENT complete: user %d get %llu satoshi\n", pi->receiver_index, pi->amount);
    }

    // initialize vector
    state.payments.clear(); // this is more efficient
    // vector<PaymentInfo>(state.payments).swap(state.payments); // -> this causes performance degrade

    // deals with routing fees for host
    state.pending_routing_fee += state.pending_routing_fee_in_round;
    state.pending_routing_fee_in_round = 0;

    //
    // 2. deals with settle requests
    //

    int settle_result = ecall_make_settle_transaction(settle_transaction_ret, settle_tx_len);
    if (settle_result != NO_ERROR) {
        // cannot make settlement tx yet (ERR_SETTLE_NOT_READY or ERR_TOO_LOW_SETTLE_FEE)
        // printf("cannot make settlement tx yet\n");
        settle_tx_len = 0;
    }

    // 
    // 3. backup data
    //

    int seal_return = ecall_seal_state(sealed_state, sealed_state_len);
    if (seal_return != NO_ERROR) {
        // sealing failed (rare & abnormal situation)

    // 
        // TODO: rollback all changes in this process_round()
    //

        // mutex unlock
        sgx_thread_mutex_unlock(&state_mutex);

        // printf("process round failed, rollback all changes\n");
        return seal_return;
    }

    // mutex unlock
    sgx_thread_mutex_unlock(&state_mutex);

    // printf("process round complete\n");
    return NO_ERROR;
}

// deals with the deposit tx in the newly inserted block
// TODO: maybe need to change name: manager_address -> keyid (need to check)
void deal_with_deposit_tx(const char* manager_address, int manager_addr_len, const char* tx_hash, int tx_hash_len, int tx_index, const char* script, int script_len, unsigned long long amount, unsigned long long block_number) {

    // will take some of the deposit to pay tx fee later
    unsigned long long balance_for_tx_fee = state.avg_tx_fee_per_byte * TX_INPUT_SIZE * TAX_RATE_FOR_SETTLE_TX;

    // will take some of the deposit to induce rouTEE host not to forcely terminate the rouTEE program (= incentive driven agent assumption)
    // = just simply pay routing fee

    // check sender sent enough deposit amount
    unsigned long long minimum_amount_of_deposit = balance_for_tx_fee + state.min_routing_fee;
    if (amount <= minimum_amount_of_deposit) {
        printf("too low amount of deposit, minimum amount is %llu\n", minimum_amount_of_deposit);
        return;
    }

    int sender_index;
    DepositRequest* dr;
    if (tx_hash_len == SGX_RSA3072_KEY_SIZE) {
        // sender_addr = string(manager_address, manager_addr_len);
        sender_index = 0; // TODO: how should set this?
    }
    else {
        // get the deposit request for this deposit tx
        dr = state.deposit_requests[string(manager_address, manager_addr_len)];

        // check the user exists
        sender_index = dr->beneficiary_index;        
    }

    if (sender_index > state.users.size()) {
        // sender is not in the state, create new account
        // Only available when debug
        Account acc;
        acc.balance = 0;
        acc.nonce = 0;
        acc.latest_SPV_block_number = 0;
        state.users.push_back(acc);
    }

    // now take some of the deposit
    state.fee_fund += balance_for_tx_fee;
    state.pending_routing_fee += state.min_routing_fee;

    // update user's balance
    unsigned long long balance_for_user = amount - balance_for_tx_fee - state.min_routing_fee;
    state.users[sender_index].balance += balance_for_user;

    // update total balances
    state.total_balances += balance_for_user;

    // update user's min_requested_block_number
    if (balance_for_user > 0) {
        state.users[sender_index].min_requested_block_number = block_number;
    }

    // add deposit
    Deposit* deposit = new Deposit;
    // Use hard-coded tx hash for debugging
    deposit->tx_hash = (tx_hash_len == SGX_RSA3072_KEY_SIZE)? "dbc95751f2a57e0ffde6b288162a72ae8e0d45dc87cf00d0ba909bbdde31d700" : string(tx_hash, tx_hash_len);
    deposit->tx_index = tx_index;
    deposit->script = string(script, script_len);
    if (tx_hash_len == SGX_RSA3072_KEY_SIZE) {
        deposit->manager_private_key = "cQzmrNwgfV8MVncGfUcKfaz5s6YegeJARpYPhrjbF6SBPRVQLc9e";
    }
    else {
        deposit->manager_private_key = dr->manager_private_key;
    }
    state.deposits.push(deposit);

    if (tx_hash_len != SGX_RSA3072_KEY_SIZE) {
        // delete deposit request
        delete dr;
        state.deposit_requests.erase(string(manager_address, manager_addr_len));
    }

    // // add deposit
    // Deposit* deposit = new Deposit;
    // deposit->tx_hash = string(tx_hash, tx_hash_len);
    // deposit->tx_index = tx_index;
    // deposit->script = string(script, script_len);
    // deposit->manager_private_key = dr->manager_private_key;
    
    // state.deposits.push(deposit);

    // // delete deposit request
    // delete dr;
    // state.deposit_requests.erase(string(manager_address, manager_addr_len));

    // increase state id
    state.stateID++;

    // for debugging
    state.d_total_deposit += amount;
    state.d_total_balances_for_settle_tx_fee += balance_for_tx_fee;

    // print result
    if (doPrint) {
        if (tx_hash_len != SGX_RSA3072_KEY_SIZE) {
            printf("deal with new deposit tx -> user: %d / balance += %llu / tx fee += %llu\n", dr->beneficiary_index, balance_for_user, balance_for_tx_fee);
        }
        else {
            printf("deal with new deposit tx -> user: %s / balance += %llu / tx fee += %llu\n", manager_address, balance_for_user, balance_for_tx_fee);
        }
    }

    return;
}

// this is not ecall function, but this can be used as ecall to debugging
void deal_with_settlement_tx() {

    // get this settle tx's info
    // settle txs are included in bitcoin with sequencial order, so just get the first pending settle tx from queue
    PendingSettleTxInfo* psti = state.pending_settle_tx_infos.front();
    state.pending_settle_tx_infos.pop();

    // confirm routing fee for this settle tx
    state.confirmed_routing_fee += psti->to_be_confirmed_routing_fee;

    // print result
    if (doPrint) {
        // printf("deal with settle tx -> rouTEE host got paid pending routing fee: %llu satoshi\n", psti->to_be_confirmed_routing_fee);
    }

        // dequeue pending settle requests for this settle tx (print for debugging, can delete this later)
        int queue_size = psti->pending_settle_requests.size();
        for (int i = 0; i < queue_size; i++) {
            SettleRequest* sr = psti->pending_settle_requests.front();
            // printf("deal with settle tx -> user: %s / requested %llu satoshi (paid tax: %llu satoshi)\n", sr.address, sr.amount, sr.balance_for_settle_tx_fee);
            psti->pending_settle_requests.pop();
            delete sr;
        }

        // dequeue used deposits for this settle tx (print for debugging, can delete this later)
        queue_size = psti->used_deposits.size();
        for (int i = 0; i < queue_size; i++) {
            Deposit* deposit = psti->used_deposits.front();
            // printf("deal with settle tx -> used deposit hash: %s\n", deposit.tx_hash);
            psti->used_deposits.pop();
            delete deposit;
        }

    delete psti;

    return;
}

bool verify_block_header(CBlockHeader& blockHeader){
    CBlockHeader bh = blockHeader;

    if (!CheckProofOfWork(bh.GetHash(), bh.nBits, chainparams.GetConsensus())){
        return false;
    }
    if ((bh.nVersion == genesis.nVersion) && (bh.hashMerkleRoot == genesis.hashMerkleRoot) && (bh.nTime == genesis.nTime)
        && (bh.nNonce == genesis.nNonce) && (bh.nBits == genesis.nBits) && (bh.hashPrevBlock == genesis.hashPrevBlock)){
        return true;
    }
    if(bh.nBits == GetNextWorkRequired(lastIndex, &bh, chainparams.GetConsensus())){
        CBlockIndex* pindexNew = new CBlockIndex(bh);
        pindexNew->pprev = lastIndex;
        pindexNew->nHeight = pindexNew->pprev->nHeight+1;
        pindexNew->BuildSkip();
        lastIndex = pindexNew;
        return true;
    }
    return false;
} 

bool verify_block(CBlock& block){
    CBlockHeader bh = block.GetBlockHeader();

    // return verify_block_header(bh);

    if (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())){
        return false;
    }
    if ((bh.nVersion == genesis.nVersion) && (bh.hashMerkleRoot == genesis.hashMerkleRoot) && (bh.nTime == genesis.nTime)
        && (bh.nNonce == genesis.nNonce) && (bh.nBits == genesis.nBits) && (bh.hashPrevBlock == genesis.hashPrevBlock)){
        return true;
    }
    if (bh.nBits == GetNextWorkRequired(lastIndex, &bh, chainparams.GetConsensus()) && bh.hashMerkleRoot == BlockMerkleRoot(block)){
        CBlockIndex* pindexNew = new CBlockIndex(bh);
        pindexNew->pprev = lastIndex;
        pindexNew->nHeight = pindexNew->pprev->nHeight+1;
        pindexNew->BuildSkip();
        lastIndex = pindexNew;
        return true;
    }
    return false;
} 

int ecall_insert_block(int block_number, const char* hex_block, int hex_block_len) {
    // 
    // TODO: BITCOIN
    // SPV verify the new bitcoin block
    // verify tx merkle root hash
    // iterate txs to call deal_with_deposit_tx() when find deposit tx
    //             to call deal_with_settlement_tx() when find settlement tx
    // update average tx fee (state.avg_tx_fee_per_byte)
    // insert the block to state.blocks
    // 
    CBlock block;
    if (!DecodeHexBlk(block, string(hex_block, hex_block_len))) {
        printf("Invalid block hex string was given\n");
        return ERR_INVALID_PARAMS;
    };

    if (!verify_block(block)) {
        printf("Invalid block was inserted\n");
        return ERR_INVALID_PARAMS;
    }

    if (block_number != (state.latest_block_number+1)) {
        printf("Invalid block with inproper block number (this is not the next block)\n");
        return ERR_INVALID_PARAMS;
    }

    // printf("block info: %s, %d\n\n", block.ToString().c_str(), block.vtx.size());
    // printf("tx_vout: %s\n", block.vtx[0]->vout[0].ToString().c_str());
    CTransactionRef transaction;
    string txid;
    CTxDestination tx_dest;
    string keyID;
    int tx_index;
    unsigned long long amount;
    string script;
    string pending_settle_tx_hash;

    unsigned int total_tx_size = 0;

    for (int tx_index = 0; tx_index < block.vtx.size(); tx_index++){
        // printf("vtx=: %s\n\n", block.vtx[tx_index]->vout[0].ToString().c_str());
        transaction = block.vtx[tx_index];
        if (!ExtractDestination(transaction->vout[0].scriptPubKey, tx_dest)) {
            printf("Extract Destination Error\n\n");
            return ERR_INVALID_PARAMS;
            // printf("rr: %d\n\n", tx_dest.class_type);
        }

        keyID = HexStr(*tx_dest.keyID);
        script = HexStr(transaction->vout[0].scriptPubKey);
        txid = transaction->GetHash().GetHex();
        amount = transaction->vout[0].nValue;
        // script = transaction->vout[0].scriptPubKey;

        pending_settle_tx_hash = state.pending_settle_tx_infos.front()->tx_hash;

        if (state.deposit_requests.find(keyID) != state.deposit_requests.end()) {
            // printf("deal_with_deposit_tx called\n");
            deal_with_deposit_tx(keyID.c_str(), keyID.length(), txid.c_str(), txid.length(), tx_index, script.c_str(), script.length(), amount, block_number);
        }
        else if (txid.compare(pending_settle_tx_hash) == 0) {
            // printf("deal_with_settlement_tx called\n");
            deal_with_settlement_tx();
        }
        
        if (!transaction->IsCoinBase()) {
            total_tx_size += transaction->GetTotalSize();
        }
        
        // printf("TX: %s\n", block.vtx[tx_index]->GetHash().GetHex().c_str());
        // printf("tx_vout 0: %lld\n", block.vtx[tx_index]->vout[0].nValue);
    }

    int nSubsidyHalvened = block_number / chainparams.GetConsensus().nSubsidyHalvingInterval;
    unsigned long long block_reward = 5000000000;
    while (nSubsidyHalvened != 0) {
        block_reward /= 2;
        nSubsidyHalvened--;
    }

    state.latest_block_number += 1;
    state.block_hashes.push_back(block.GetBlockHeader().GetHash());

    if (block.vtx.size() - 1 != 0) {
        unsigned long long total_tx_fee = block.vtx[0]->vout[0].nValue - block_reward;
        state.accumulated_tx_fee += total_tx_fee;
        state.accumulated_tx_size += total_tx_size;
        state.tx_fee_infos.push(TxFeeInfo(total_tx_fee, total_tx_size));

        if (state.tx_fee_infos.size() > QUEUING_TX_INFO_NUM) {
            TxFeeInfo old_tx_fee_info = state.tx_fee_infos.front();

            state.accumulated_tx_fee -= old_tx_fee_info.total_tx_fee;
            state.accumulated_tx_size -= old_tx_fee_info.total_tx_size;

            state.tx_fee_infos.pop();
        }

        state.avg_tx_fee_per_byte = state.accumulated_tx_fee / state.accumulated_tx_size;
        // printf("avg. tx fee: %llu, %llu, %llu\n", state.accumulated_tx_fee , state.accumulated_tx_size, state.avg_tx_fee_per_byte);
    }

    // printf("block number: %d\n\n", block_number);

    return NO_ERROR;
}

int ecall_insert_block_header(int block_number, const char* hex_block_header, int hex_block_header_len) {
    CBlockHeader block_header;

    if (!DecodeHexBlkHeader(block_header, string(hex_block_header, hex_block_header_len))) {
        printf("Invalid block header hex string was given\n");
        return ERR_INVALID_PARAMS;
    };

    if (!verify_block_header(block_header)) {
        printf("Invalid block header was inserted\n");
        return ERR_INVALID_PARAMS;
    }

    if (block_number != (state.latest_block_number+1)) {
        printf("Invalid block with inproper block number (this is not the next block)\n");
        return ERR_INVALID_PARAMS;
    }

    state.latest_block_number += 1;
    state.block_hashes.push_back(block_header.GetHash());

    return NO_ERROR;
}

int ecall_get_current_block_number(int* current_block_number) {
    *current_block_number = state.latest_block_number;

    return NO_ERROR;
}

int make_encrypted_response(const char* response_msg, sgx_aes_gcm_128bit_key_t *session_key, char* encrypted_response, int* encrypted_response_len) {

    // return encrypted response to client
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
    
    // sgx_aes_gcm_128bit_key_t *session_key = state.session_keys[session_ID];
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
        encryption_result = make_encrypted_response(error_to_msg(ERR_DECRYPT_FAILED).c_str(), session_key, encrypted_response, encrypted_response_len);
        if (encryption_result != NO_ERROR) {
            // TODO: if encryption failed, send rouTEE's signature for the failed cmd
            // to make client believe that the encrpytion really failed
            return ERR_ENCRYPT_FAILED;
        }
        return NO_ERROR;
    }
    
    char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
	memcpy(decMessage, p_dst, decMessageLen);
    decMessage[decMessageLen] = '\0';

    //
    // execute decrypted cmd
    //
    // @ Luke Park
    // mutex lock
    sgx_thread_mutex_lock(&state_mutex);

    // parse the command to get parameters
    vector<string> params;
    string cmd = string(decMessage, decMessageLen);
    split(cmd, params, ' ');

    const int decCommandLen = decMessageLen - SGX_RSA3072_KEY_SIZE - 1;

    char *decCommand = (char *) malloc((decCommandLen+1)*sizeof(char));
    memcpy(decCommand, decMessage, decCommandLen);
    decCommand[decCommandLen] = '\0';

    char *decSignature = decMessage + decCommandLen + 1;

    // printf("decCommand: %s, %d\n\n", decCommand, decCommandLen);

    // find appropriate operation
    char operation = params[0][0];
    int operation_result;
    char response_msg[64];
    switch(operation) {
        // ADD_USER operation
        case OP_ADD_USER:
            // in this case: decSignature is a public key (sigLen = keyLen = SGX_RSA3072_KEY_SIZE)
            operation_result = secure_add_user(decCommand, decCommandLen, decSignature, response_msg);
            break;
        // ADD_DEPOSIT operation
        case OP_GET_READY_FOR_DEPOSIT:
            // in this case: this operation do not require signature
            operation_result = secure_get_ready_for_deposit(decCommand, decCommandLen, response_msg);
            break;
        // UPDATE_BOUNDARY_BLOCK operation
        case OP_UPDATE_LATEST_SPV_BLOCK:
            operation_result = secure_update_latest_SPV_block(decCommand, decCommandLen, decSignature, response_msg);
            break;
        // MULTI-HOP_PAYMENT operation
        case OP_DO_MULTIHOP_PAYMENT:
            operation_result = secure_do_multihop_payment(decCommand, decCommandLen, decSignature, response_msg);
            break;
        // SETTLEMENT operation
        case OP_SETTLE_BALANCE:
            operation_result = secure_settle_balance(decCommand, decCommandLen, decSignature, response_msg);
            break;
        // invalid opcode
        default:
            operation_result = ERR_INVALID_OP_CODE;
            break;
    }
    // free memory
    free(decMessage);
    free(decCommand);

    //
    // encrypt response
    //
    // @ Luke Park
    // mutex unlock
    sgx_thread_mutex_unlock(&state_mutex);

    // encrypt the response for client (response is already set when ADD_DEPOSIT operation successed, so do not change)
    if (operation != OP_GET_READY_FOR_DEPOSIT || operation_result != NO_ERROR) {
        string response = error_to_msg(operation_result);
        memcpy((char*)response_msg, response.c_str(), response.length()+1);
        if (operation_result != NO_ERROR) {
            printf("ERROR: execution failed -> %s\n", response.c_str());
        }
    }
    encryption_result = make_encrypted_response(response_msg, session_key, encrypted_response, encrypted_response_len);
    if (encryption_result != NO_ERROR) {
        // TODO: if encryption failed, send rouTEE's signature for the failed cmd
        // to make client believe that the encrpytion really failed
        printf("ERROR: encryption failed");
        return ERR_ENCRYPT_FAILED;
    }

    // print result
    if (doPrint) {
        // printf("decrypted secure command: %s\n", decMessage);
        // printf("secure command result: %s\n", response_msg);
    }

    // return NO_ERROR to hide the real ecall result from rouTEE host
    return NO_ERROR;
}

void ecall_initialize() {
    printf("start initilizing RouTEE\n");

    // initialize ECC State for Bitcoin Library
    initializeECCState();

    // set users's capacity
    state.users.reserve(300005); 

    // set temporary state.block_hashes for experiment
    int block_num_to_insert = 52560+1; // 52560 blocks/year (96B per hash)
    state.latest_block_number = block_num_to_insert-1;
    state.block_hashes.reserve(block_num_to_insert);
    for (int i = 0; i < block_num_to_insert; i++) {
        // hex string has 2x the space than bytes (i.e., BITCOIN_HEADER_HASH_LEN*2)
        string block_hash_str = long_long_to_string(i);
        while(block_hash_str.length() != BITCOIN_HEADER_HASH_LEN*2) {
            block_hash_str = "0" + block_hash_str;
        }

        uint256 block_hash;
        block_hash.SetHex(string(block_hash_str, BITCOIN_HEADER_HASH_LEN));

        state.block_hashes.push_back(block_hash);
        // printf("block_hash_str: %s\n", block_hash_str.c_str());
        // printf("state.block_hashes[%d]: %s\n", i, state.block_hashes[i].ToString().c_str());
    }
    printf("latest block number in RouTEE: %d\n", state.latest_block_number);
    printf("\n");
}

// seal RouTEE state as an encrypted file
int ecall_seal_state(char* sealed_state, int* sealed_state_len) {

    // serialize state
    int userNum = state.users.size();
    int sizePerAccount = 32 + BITCOIN_ADDRESS_LEN;
    if (doSealPubkey) {
        sizePerAccount += RSA_PUBLIC_KEY_LEN;
    }
    int state_bytes_len = userNum*sizePerAccount;
    char *state_bytes = new char[state_bytes_len];
    int offset = 0;
    const unsigned char* cptr;
    for (int i = 0; i < state.users.size(); i++){
        cptr = (const unsigned char*)&state.users[i];
        memcpy(state_bytes+offset, cptr, sizePerAccount); // Account fields
        offset += sizePerAccount;
    }
    // printf("serialize success\n");

    // check serialize result
    // for (int i = 0; i < userNum*sizePerAccount;) {
    //     printf("balance: ");
    //     for (int j = 0; j < 8; j++) {
    //         printf("%02X ", state_bytes[i+j]);
    //     }
    //     printf("\n");
    //     i += 8;

    //     printf("nonce: ");
    //     for (int j = 0; j < 8; j++) {
    //         printf("%02X ", state_bytes[i+j]);
    //     }
    //     printf("\n");
    //     i += 8;

    //     printf("source block: ");
    //     for (int j = 0; j < 8; j++) {
    //         printf("%02X ", state_bytes[i+j]);
    //     }
    //     printf("\n");
    //     i += 8;

    //     printf("boundary block: ");
    //     for (int j = 0; j < 8; j++) {
    //         printf("%02X ", state_bytes[i+j]);
    //     }
    //     printf("\n");
    //     i += 8;

    //     printf("settle addr: ");
    //     for (int j = 0; j < BITCOIN_ADDRESS_LEN; j++) {
    //         printf("%c", state_bytes[i+j]);
    //     }
    //     printf("\n");
    //     i += BITCOIN_ADDRESS_LEN;

    //     if (doSealPubkey) {
    //         printf("pubkey: ");
    //         for (int j = 0; j < RSA_PUBLIC_KEY_LEN; j++) {
    //             printf("%c", state_bytes[i+j]);
    //         }
    //         printf("\n");
    //         i += RSA_PUBLIC_KEY_LEN;
    //     }

    //     printf("\n");
    // }

    // seal the state
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)state_bytes_len);
    *sealed_state_len = sealed_data_size;
    if (sealed_data_size == UINT32_MAX) {
        return ERR_SGX_ERROR_UNEXPECTED;
    }
    sgx_sealed_data_t *sealed_state_buffer = (sgx_sealed_data_t *) malloc(sealed_data_size);
    sgx_status_t status = sgx_seal_data(0, NULL, (uint32_t)state_bytes_len, (uint8_t *) state_bytes, sealed_data_size, sealed_state_buffer);
    if (status != SGX_SUCCESS) {
        return ERR_SEAL_FAILED;
    }
    // printf("sealing success: sealed data size: %d\n", sealed_data_size);

    // copy sealed state to the app buffer
    memcpy(sealed_state, sealed_state_buffer, sealed_data_size);
    free(sealed_state_buffer);
    delete[] state_bytes;
    // printf("copy sealed data success\n");
    return NO_ERROR;
}

// unseal RouTEE state from an encrypted file
int ecall_load_state(const char* sealed_state, int sealed_state_len) {
    // for edge8r
    (void) sealed_state_len;

    // unseal the sealed private key
    uint32_t unsealed_state_length = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *) sealed_state);
    uint8_t* unsealed_state = new uint8_t[unsealed_state_length];
    sgx_status_t status = sgx_unseal_data((const sgx_sealed_data_t *) sealed_state, NULL, 0, unsealed_state, &unsealed_state_length);
    if (status != SGX_SUCCESS) {
        // printf("decryption failed\n");
        return ERR_UNSEAL_FAILED;
    }
    // printf("decryption success\n");

    // clear state.users map before load
    if (state.users.size() != 0) {
        printf("clear state.users map before load\n");
        state.users.clear();
        state.users.reserve(300001);
    }

    // load global state
    int sizePerAccount = 32 + BITCOIN_ADDRESS_LEN;
    if (doSealPubkey) {
        sizePerAccount += RSA_PUBLIC_KEY_LEN;
    }
    int user_index = 0;
    for (int i = 0; i < unsealed_state_length;) {
        // get Account fields
        Account acc;
        memcpy(&acc, unsealed_state+i, sizePerAccount);
        i += sizePerAccount;

        state.users.push_back(acc);
        
        // print load result
        // printf("user index: %d\n", user_index);
        // printf("balance: %llu\n", acc.balance);
        // printf("nonce: %llu\n", acc.nonce);
        // printf("source block: %llu\n", acc.min_requested_block_number);
        // printf("boundary block: %llu\n", acc.latest_SPV_block_number);
        // printf("settle address: %s\n", string(acc.settle_address, BITCOIN_ADDRESS_LEN).c_str());
        // printf("\n");
        user_index++;
    }
    delete[] unsealed_state;
    // printf("success loading state!\n");

    return NO_ERROR;
}
