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
    state.routing_fee = strtoull(routing_fee, NULL, 10);
    
    // print result
    if (doPrint) {
        printf("set routing fee as %llu satoshi\n", state.routing_fee);
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
        return ERR_TOO_LOW_AMOUNT_TO_SETTLE;
    }

    // check there is enough confirmed routing fee to settle
    if (amount > state.routing_fee_confirmed) {
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // push new waiting settle request
    SettleRequest* sr = new SettleRequest;
    sr->address = state.fee_address;
    sr->amount = amount;
    state.settle_requests_waiting.push(sr);

    // update host's routing fees
    state.routing_fee_confirmed -= amount;
    state.routing_fee_settled += amount;

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

    printf("\n\n\n***** owner info *****\n\n");
    printf("owner address: %s\n", state.owner_address.c_str());

    printf("\n\n\n\n\n***** user account info *****\n\n");
    for (map<string, Account*>::iterator iter = state.users.begin(); iter != state.users.end(); iter++){
        printf("address: %s -> balance: %llu / nonce: %llu / min_requested_block_number: %llu / latest_SPV_block_number: %llu\n", 
            (iter->first).c_str(), iter->second->balance, iter->second->nonce, iter->second->min_requested_block_number, iter->second->latest_SPV_block_number);
    }
    printf("\n=> total %d accounts / total %llu satoshi\n", state.users.size(), state.total_balances);

    printf("\n\n\n\n\n***** deposit requests *****\n\n");
    for (map<string, DepositRequest*>::iterator iter = state.deposit_requests.begin(); iter != state.deposit_requests.end(); iter++){
        printf("manager key id: %s -> sender address: %s / manager address: %s / block number:%llu\n", 
            (iter->first).c_str(), iter->second->sender_address.c_str(), iter->second->manager_address.c_str(), iter->second->block_number);
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
    queue_size = state.settle_requests_waiting.size();
    for (int i = 0; i < queue_size; i++) {
        SettleRequest* sr = state.settle_requests_waiting.front();
        printf("user address: %s / amount: %llu satoshi\n", sr->address.c_str(), sr->amount);

        // to iterate queue elements
        state.settle_requests_waiting.pop();
        state.settle_requests_waiting.push(sr);
    }

    printf("\n\n\n\n\n***** pending settle requests *****\n\n");
    queue_size = state.pending_settle_tx_infos.size();
    unsigned long long pending_routing_fees = 0;
    for (int i = 0; i < queue_size; i++) {
        PendingSettleTxInfo* psti = state.pending_settle_tx_infos.front();
        printf("pending settle tx %d: pending routing fee: %llu satoshi\n", i, psti->pending_routing_fees);
        pending_routing_fees += psti->pending_routing_fees;
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
            printf("    user address: %s / settle amount: %llu satoshi\n", sr->address.c_str(), sr->amount);

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
    printf("routing fee per payment: %llu satoshi\n", state.routing_fee);
    printf("routing fee address: %s\n", state.fee_address.c_str());
    printf("waiting routing fees: %llu satoshi\n", state.routing_fee_waiting);
    printf("pending routing fees: %llu satoshi\n", pending_routing_fees);
    printf("confirmed routing fees: %llu satoshi\n", state.routing_fee_confirmed);
    printf("settled routing fees = %llu\n", state.routing_fee_settled);

    printf("\n\n\n\n\n***** check correctness *****\n\n");
    bool isCorrect = true;
    printf("d_total_deposit = %llu\n\n", state.d_total_deposit);
    printf("total_balances = %llu\n", state.total_balances);
    printf("d_total_settle_amount = %llu\n", state.d_total_settle_amount);
    printf("d_total_balances_for_settle_tx_fee = %llu\n", state.d_total_balances_for_settle_tx_fee);
    printf("routing_fee_waiting = %llu\n", state.routing_fee_waiting);
    printf("pending_routing_fees = %llu\n", pending_routing_fees);
    printf("routing_fee_confirmed = %llu\n", state.routing_fee_confirmed);
    printf("routing_fee_settled = %llu\n", state.routing_fee_settled);
    printf("current block number = %llu\n", state.block_number);

    unsigned long long calculated_total_deposit = 0;
    calculated_total_deposit += state.total_balances;
    calculated_total_deposit += state.d_total_settle_amount;
    calculated_total_deposit += state.d_total_balances_for_settle_tx_fee;
    calculated_total_deposit += state.routing_fee_waiting;
    calculated_total_deposit += pending_routing_fees;
    calculated_total_deposit += state.routing_fee_confirmed;
    calculated_total_deposit += state.routing_fee_settled;
    if (state.d_total_deposit != calculated_total_deposit) {
        printf("\n=> ERROR: total deposit is not correct, some balances are missed\n\n");
        isCorrect = false;
    }
    printf("\n");

    printf("d_total_balances_for_settle_tx_fee = %llu\n\n", state.d_total_balances_for_settle_tx_fee);
    printf("balances_for_settle_tx_fee = %llu\n", state.balances_for_settle_tx_fee);
    printf("d_total_settle_tx_fee = %llu\n", state.d_total_settle_tx_fee);
    unsigned long long calculated_total_balances_for_settle_tx_fee = 0;
    calculated_total_balances_for_settle_tx_fee += state.balances_for_settle_tx_fee;
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

// ADD_DEPOSIT operation
int secure_get_ready_for_deposit(const char* command, int cmd_len, const char* sessionID, int sessionID_len, const char* signature, int sig_len, const char* response_msg) {

    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");
    char* _sender_address = strtok(NULL, " ");
    if (_sender_address == NULL) {
        printf("No sender address\n");
        return ERR_INVALID_PARAMS;
    }

    // check if this is a valid bitcoin address
    string sender_address(_sender_address, BITCOIN_ADDRESS_LEN);
    if (!CBitcoinAddress(sender_address).IsValid()) {
        printf("Invalid sender address\n");
        return ERR_INVALID_PARAMS;
    }

    // check if the user exists
    if (state.users.find(sender_address) == state.users.end()) {
        printf("No sender account exist in rouTEE\n");
        return ERR_NO_USER_ACCOUNT;
    }

    // verify signature
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, state.users[sender_address]->public_key.c_str(), SGX_RSA3072_KEY_SIZE);
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

    // initialize ECC State for Bitcoin Library
    initializeECCState();
    // randomly generate a bitcoin address to be paid by the user (manager address)
    CKey key;
    key.MakeNewKey(true /* compressed */);
    CPubKey pubkey = key.GetPubKey();

    CKeyID keyid = pubkey.GetID();
    CTxDestination* dest = new CTxDestination;
    dest->class_type = 2;
    dest->keyID = &keyid;
    CScript script = GetScriptForDestination(*dest);

    // get redeem script
    std::string script_asm = ScriptToAsmStr(script);

    // TODO: clean up using the bitcoin core code! For now this works as we hardcode the redeem scripts...
    std::string redeem_script;
    if (debug) {
        redeem_script = "76a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac"; // hard coded for tests!
    } else {
        std::string hash_string = script_asm.substr(18, 40); // 18 is offset of hash in asm, 40 is length of RIPEMD160 in hex
        redeem_script = "76a914" + hash_string + "88ac";  // the P2PKH script format
    }

    CBitcoinAddress address;
    address.Set(pubkey.GetID());

    std::string generated_address = address.ToString();
    std::string generated_public_key = HexStr(key.GetPubKey());
    std::string generated_private_key = CBitcoinSecret(key).ToString();

    // get latest block in rouTEE
    // temp code
    unsigned long long latest_block_number = state.block_number;

    // add to pending deposit list
    DepositRequest *deposit_request = new DepositRequest;
    deposit_request->manager_private_key = generated_private_key;
    deposit_request->manager_address = generated_address;
    deposit_request->sender_address = sender_address;
    deposit_request->block_number = latest_block_number;
    state.deposit_requests[keyid.ToString()] = deposit_request;
    
    // print result
    if (doPrint) {
        // printf("manager private key: %s\n", generated_private_key.c_str());
        printf("ADD_DEPOSIT success: random manager address: %s / block number: %llu\n", generated_address.c_str(), latest_block_number);
    }

    // send random address & block info to the sender
    //response_msg = (generated_address + " " + long_long_to_string(latest_block_number)).c_str();

    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// operation function for secure_command
// SETTLEMENT operation: make settle request for user balance
int secure_settle_balance(const char* command, int cmd_len, const char* sessionID, int sessionID_len, const char* signature, int sig_len, const char* response_msg) {

    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");

    char* _user_address = strtok(NULL, " ");
    if (_user_address == NULL) {
        printf("No user address for settle balance\n");
        return ERR_INVALID_PARAMS;
    }
    
    char* _amount = strtok(NULL, " ");
    if (_amount == NULL) {
        printf("No amount parameter for settle balance\n");
        return ERR_INVALID_PARAMS;
    }

    string user_address(_user_address, BITCOIN_ADDRESS_LEN);
    unsigned long long amount = strtoull(_amount, NULL, 10);
    
    // check if it is a valid bitcoin address
    if (!CBitcoinAddress(user_address).IsValid()) {
        printf("Invalid user address for settle balance\n");
        return ERR_INVALID_PARAMS;
    }

    // check if the user exists
    map<string, Account*>::iterator iter = state.users.find(user_address);
    if (iter == state.users.end()) {
        printf("No user account exist in rouTEE\n");
        return ERR_NO_USER_ACCOUNT;
    }
    Account* user_acc = iter->second;

    // verify signature
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, user_acc->public_key.c_str(), SGX_RSA3072_KEY_SIZE);
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

    // amount should be bigger than minimum settle amount
    // minimum settle amount = tax to make settlement tx with only 1 settle request user = maximum tax to make settle tx
    unsigned long long minimun_settle_amount = (TX_INPUT_SIZE + TX_OUTPUT_SIZE) * state.avg_tx_fee_per_byte * TAX_RATE_FOR_SETTLE_TX;
    if (amount <= minimun_settle_amount) {
        printf("too low amount -> minimun_settle_amount: %llu\n", minimun_settle_amount);
        return ERR_TOO_LOW_AMOUNT_TO_SETTLE;
    }

    // check the user has enough balance
    if (user_acc->balance < amount) {
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // sgx_thread_mutex_lock(&state_mutex);

    // push new waiting settle request
    SettleRequest* sr = new SettleRequest;
    sr->address = user_address;
    sr->amount = amount;
    state.settle_requests_waiting.push(sr);

    // set user's account
    user_acc->balance -= amount;
    user_acc->nonce++; // prevent payment replay attack    

    // reset user's max source block number if balance becomes 0
    if (user_acc->balance == 0) {
        user_acc->min_requested_block_number = 0;
    }

    // update total balances
    state.total_balances -= amount;

    // increase state id
    state.stateID++;

    // for debugging
    state.d_total_settle_amount += amount;

    // print result
    if (doPrint) {
        printf("SETTLEMENT success: user %s requested settlement: %llu satoshi\n", user_address.c_str(), amount);
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

    // 
    // TODO: check rouTEE is ready to settle
    // ex. check there is no pending settle tx || at least 1 user requested settlement
    //
    if (state.pending_settle_tx_infos.size() != 0 || state.settle_requests_waiting.size() == 0) {
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
    PendingSettleTxInfo* psti = new PendingSettleTxInfo;
    psti->tx_hash = "0x_settle_tx_hash";
    psti->pending_balances = 0;
    int tx_input_num = state.deposits.size();
    int settle_users_num = state.settle_requests_waiting.size();
    int tx_output_num = settle_users_num;
    unsigned long long balance_for_settle_tx_fee = (tx_output_num * TX_OUTPUT_SIZE) / settle_users_num * state.avg_tx_fee_per_byte * TAX_RATE_FOR_SETTLE_TX;
    if (state.total_balances != 0 || state.routing_fee_waiting != 0 || state.routing_fee_confirmed != 0) {
        tx_output_num += 1; // +1 means leftover_deposit
        balance_for_settle_tx_fee = ((tx_output_num * TX_OUTPUT_SIZE) + TX_INPUT_SIZE) / settle_users_num * state.avg_tx_fee_per_byte * TAX_RATE_FOR_SETTLE_TX;
    }
    else {
        // so just give balances_for_settle_tx_fee to state.fee_address
        unsigned long long bonus = state.balances_for_settle_tx_fee;
        state.settle_requests_waiting.front()->amount += bonus;
        state.d_total_balances_for_settle_tx_fee -= bonus;
        state.routing_fee_settled += bonus;
        state.balances_for_settle_tx_fee = 0;
        balance_for_settle_tx_fee = (TX_INPUT_SIZE + TX_OUTPUT_SIZE) * state.avg_tx_fee_per_byte;

        // print result
        if (doPrint) {
            // there is no user balance left, no routing fee left
            // this means this settle tx is to settle all routing_fee_confirmed alone
            printf("there is nothing left to settle. this settle tx cleans all the things.\n");
            printf("bonus for clean-up settle tx: give %llu satoshi to fee address\n", bonus);
        }
    }

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

    while(!state.settle_requests_waiting.empty()) {
        SettleRequest* sr = state.settle_requests_waiting.front();
        psti->pending_balances += sr->amount;
        if (doPrint) {
            printf("settle tx output: to %s / %llu satoshi\n", sr->address.c_str(), sr->amount);
        }

        // change settle requests status: from waiting to pending
        // & calculate settlement tax
        state.settle_requests_waiting.pop();
        sr->balance_for_settle_tx_fee = balance_for_settle_tx_fee;
        state.balances_for_settle_tx_fee += sr->balance_for_settle_tx_fee;
        state.d_total_balances_for_settle_tx_fee += sr->balance_for_settle_tx_fee;
        state.d_total_settle_amount -= sr->balance_for_settle_tx_fee;

        unsigned long long settle_amount = sr->amount - sr->balance_for_settle_tx_fee;
        output_string += "\"" + sr->address + "\":" + satoshi_to_bitcoin(settle_amount) + ",";
        total_settle_amount += settle_amount;

        if (state.settle_requests_waiting.empty()) {
            Deposit* leftover_deposit = new Deposit;

            leftover_deposit->tx_index = tx_output_num - 1;
            leftover_deposit->manager_private_key = state.owner_private_key;

            unsigned long long total_out = state.d_total_deposit - total_settle_amount - ((tx_output_num * TX_OUTPUT_SIZE) + TX_INPUT_SIZE) * state.avg_tx_fee_per_byte;

            output_string += "\"" + state.owner_address + "\":" + satoshi_to_bitcoin(total_out) + "}";

            state.deposits.push(leftover_deposit);
            psti->leftover_deposit = leftover_deposit;
            // printf("state.d_total_deposit: %llu, total_settle_amount: %llu, total_out: %llu\n", state.d_total_deposit, total_settle_amount, total_out);
        }
        else {
            // TODO
        }
        psti->pending_settle_requests.push(sr);
    }

    psti->pending_routing_fees = state.routing_fee_waiting * psti->pending_balances / (state.total_balances + psti->pending_balances);
    state.routing_fee_waiting -= psti->pending_routing_fees;
    int settle_tx_size = TX_INPUT_SIZE * tx_input_num + TX_OUTPUT_SIZE * tx_output_num;
    psti->pending_tx_fee = state.avg_tx_fee_per_byte * settle_tx_size;
    psti->leftover_deposit->tx_hash = "0x_tx_hash"; // TODO fix (sjkim)
    state.pending_settle_tx_infos.push(psti);
    state.balances_for_settle_tx_fee -= psti->pending_tx_fee;

    // for debugging
    state.d_total_settle_tx_fee += psti->pending_tx_fee;

    // print result
    if (doPrint) {
        printf("input string: %s\n", input_string.c_str());
        printf("output string: %s\n", output_string.c_str());
        printf("settle tx intput num: %d / settle tx output num: %d\n", tx_input_num, tx_output_num);
        printf("routing fee waiting: %llu / psti->pending balances: %llu / state.total balance: %llu\n", state.routing_fee_waiting, psti->pending_balances, state.total_balances);
    }

    // printf("input string: %s\noutput string: %s\n", input_string.c_str(), output_string.c_str());
    std::string create_transaction_rpc = create_raw_transaction_rpc();
    create_transaction_rpc += input_string + " " + output_string;
    // printf("create transaction rpc: %s\n", create_transaction_rpc.c_str());
    UniValue settle_transaction = executeCommand(create_transaction_rpc);
    //std::string settle_transaction_string = remove_surrounding_quotes(settle_transaction.write());
    std::string settle_transaction_string = settle_transaction.write();
    // printf("settle_transaction_string: %s\n", settle_transaction_string.c_str());

    std::string sign_transaction_rpc = sign_raw_transaction_rpc();
    sign_transaction_rpc += settle_transaction_string.substr(1, settle_transaction_string.size() - 2) + " " + prevouts + " " + privkey + " ALL";
    // printf("sign_transaction_rpc: %s\n", sign_transaction_rpc.c_str());
    UniValue signed_settle_transaction = executeCommand(sign_transaction_rpc);
    std::string signed_settle_transaction_string = signed_settle_transaction.write();
    // printf("signed_settle_transaction_string: %s\n", signed_settle_transaction_string.c_str());

    *settle_tx_len = signed_settle_transaction_string.length();
    memcpy((char*) settle_transaction_ret, signed_settle_transaction_string.c_str(), signed_settle_transaction_string.length());

    return NO_ERROR;
}

// MULTI-HOP_PAYMENT operation: make payment & pay routing fee
int secure_do_multihop_payment(const char* command, int cmd_len, const char* sessionID, int sessionID_len, const char* signature, int sig_len, const char* response_msg) {

    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");

    char* _sender_address = strtok(NULL, " ");
    if (_sender_address == NULL) {
        printf("No sender address for multihop payment\n");
        return ERR_INVALID_PARAMS;
    }

    char* _batch_size = strtok(NULL, " ");
    if (_batch_size == NULL) {
        printf("No batch size for multihop payment\n");
        return ERR_INVALID_PARAMS;
    }

    string sender_address(_sender_address, BITCOIN_ADDRESS_LEN);
    int batch_size = atoi(_batch_size);

    // check the sender exists & has more than amount + fee to send
    map<string, Account*>::iterator iter = state.users.find(sender_address);
    if (iter == state.users.end()) {
        printf("No sender account exist in rouTEE\n");
        return ERR_NO_USER_ACCOUNT;
    }
    Account* sender_acc = iter->second;

    queue<PaymentInfo> queue;
    Account* receiver_acc;
    string receiver_address;
    unsigned long long amount;
    unsigned long long total_amount;

    for (int i = 0; i < batch_size; i++) {

        // get params from command
        char* _receiver_address = strtok(NULL, " ");
        if (_receiver_address == NULL) {
            printf("No receiver address for multihop payment\n");
            return ERR_INVALID_PARAMS;
        }

        char* _amount = strtok(NULL, " ");
        if (_amount == NULL) {
            printf("No amount parameter for multihop payment\n");
            return ERR_INVALID_PARAMS;
        }

        receiver_address = string(_receiver_address, BITCOIN_ADDRESS_LEN);
        amount = strtoull(_amount, NULL, 10);

        // check the receiver exists
        iter = state.users.find(receiver_address);
        if (iter == state.users.end()) {
            // receiver is not in the state
            printf("No receiver account for payment");
            return ERR_NO_RECEIVER;
        }
        receiver_acc = iter->second;

        // check if the receiver is ready to get paid (temporarily deprecated for easy tests) (for debugging)
        if (sender_acc->min_requested_block_number > receiver_acc->latest_SPV_block_number) {
            return ERR_RECEIVER_NOT_READY;
        }

        total_amount += amount;
        queue.push(PaymentInfo(receiver_acc, amount));
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
    if (fee < state.routing_fee) {
        return ERR_NOT_ENOUGH_FEE;
    }

    // check if the sender can afford this payments
    if (sender_acc->balance < total_amount + batch_size * fee) {
        return ERR_NOT_ENOUGH_BALANCE;
    }

    // verify signature
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, sender_acc->public_key.c_str(), SGX_RSA3072_KEY_SIZE);
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

    // execute multi-hop payments
    for (int i = 0; i < batch_size; i++) {
        PaymentInfo payment_info = queue.front();
        receiver_acc = payment_info.receiver_account;
        amount = payment_info.amount;

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

        // reset sender's max source block number if balances becomes 0
        if (sender_acc->balance == 0) {
            sender_acc->min_requested_block_number = 0;
        }

        queue.pop();
    }

    // increase state id
    state.stateID++;

    // print result
    if (doPrint) {
        printf("PAYMENT success: user %s send %llu satoshi to user %s (routing fee: %llu)\n", sender_address.c_str(), amount, receiver_address.c_str(), fee);
    }

    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// ADD_USER operation: 
int secure_add_user(const char* command, int cmd_len, const char* sessionID, int sessionID_len, const char* signature, int sig_len, const char* response_msg) {

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

    // check if the user already exists
    if (state.users.find(user_address) != state.users.end()) {
        printf("rouTEE account already exists for this public key\n");
        return ERR_NO_AUTHORITY;
    }

    // sgx_thread_mutex_lock(&state_mutex);

    // create new account for the user
    Account* acc = new Account;
    acc->balance = 0;
    acc->nonce = 0;
    acc->min_requested_block_number = 0;
    acc->latest_SPV_block_number = 0;
    acc->settle_address = settle_address;
    acc->public_key = string(signature, SGX_RSA3072_KEY_SIZE);
    state.users[user_address] = acc;
    
    // print result
    if (doPrint) {
        printf("ADD_USER success: user address: %s / settle address: %s\n", user_address.c_str(), settle_address.c_str());
    }

    // memcpy((char*) response_msg, response_str.c_str(), response_str.length() + 1);
    response_msg = ("User account has been generated! sender address: " + user_address + ", settle address: " + settle_address + "\n").c_str();

    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// UPDATE_BOUNDARY_BLOCK operation: 
int secure_update_latest_SPV_block(const char* command, int cmd_len, const char* sessionID, int sessionID_len, const char* signature, int sig_len, const char* response_msg) {

    // temply save before getting params for verifying signature later
    char cmd_tmp[cmd_len];
    memcpy(cmd_tmp, command, cmd_len);

    // get params from command
    char* _cmd = strtok((char*) command, " ");
    char* _user_address = strtok(NULL, " ");
    if (_user_address == NULL) {
        printf("No user address for update last SPV block\n");
        return ERR_INVALID_PARAMS;
    }

    char* _block_number = strtok(NULL, " ");
    if (_block_number == NULL) {
        printf("No block number for update last SPV block\n");
        return ERR_INVALID_PARAMS;
    }

    // TODO: fix
    // char* _block_hash = strtok(NULL, " ");
    // if (_block_hash == NULL) {
    //     printf("No block hash for update last SPV block\n");
    //     return ERR_INVALID_PARAMS;
    // }  

    string user_address(_user_address, BITCOIN_ADDRESS_LEN);
    unsigned long long block_number = strtoull(_block_number, NULL, 10);

    // TODO: fix
    // uint256 block_hash;
    // block_hash.SetHex(string(_block_hash, BITCOIN_HEADER_HASH_LEN));

    // check if this is a valid bitcoin address
    if (!CBitcoinAddress(user_address).IsValid()) {
        printf("Invalid user address for update last SPV block\n");
        return ERR_INVALID_PARAMS;
    }

    if (block_number > state.block_number) {
        printf("Given block number is higher than rouTEE has\n");
        return ERR_INVALID_PARAMS;
    }

    // check user has same block with rouTEE
    // TODO: fix
    // if (state.block_hash[block_number] != block_hash) {
    //     printf("Given block hash is different from rouTEE has\n");
    //     return ERR_INVALID_PARAMS;
    // }

    // check if the user exists
    map<string, Account*>::iterator iter = state.users.find(user_address);
    if (iter == state.users.end()) {
        printf("No user account exist in rouTEE\n");
        return ERR_NO_USER_ACCOUNT;
    }
    Account* user_acc = iter->second;

    // verify signature
    sgx_rsa3072_public_key_t rsa_pubkey;
    memset(rsa_pubkey.mod, 0, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_pubkey.mod, user_acc->public_key.c_str(), SGX_RSA3072_KEY_SIZE);
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
    if (user_acc->latest_SPV_block_number < block_number) {
        user_acc->latest_SPV_block_number = block_number;
    }
    else {
        // cannot change boundary block to lower block
        return ERR_CANNOT_CHANGE_TO_LOWER_BLOCK;
    }

    // print result
    if (doPrint) {
        printf("UPDATE_BOUNDARY_BLOCK success: user %s update boundary block number to %llu\n", user_address.c_str(), block_number);
    }
    
    // sgx_thread_mutex_unlock(&state_mutex);

    return NO_ERROR;
}

// deals with the deposit tx in the newly inserted block
void deal_with_deposit_tx(const char* manager_address, int manager_addr_len, const char* tx_hash, int tx_hash_len, int tx_index, const char* script, int script_len, unsigned long long amount, unsigned long long block_number) {

    // will take some of the deposit to pay tx fee later
    unsigned long long balance_for_tx_fee = state.avg_tx_fee_per_byte * TX_INPUT_SIZE * TAX_RATE_FOR_SETTLE_TX;

    // will take some of the deposit to induce rouTEE host not to forcely terminate the rouTEE program (= incentive driven agent assumption)
    // = just simply pay routing fee

    // check sender sent enough deposit amount
    unsigned long long minimum_amount_of_deposit = balance_for_tx_fee + state.routing_fee;
    if (amount <= minimum_amount_of_deposit) {
        printf("too low amount of deposit, minimum amount is %llu\n", minimum_amount_of_deposit);
        return;
    }

    string sender_addr;
    DepositRequest* dr;
    if (tx_hash_len == SGX_RSA3072_KEY_SIZE) {
        sender_addr = string(manager_address, manager_addr_len);
    }
    else {
        // get the deposit request for this deposit tx
        dr = state.deposit_requests[string(manager_address, manager_addr_len)];

        // check the user exists
        sender_addr = dr->sender_address;        
    }

    map<string, Account*>::iterator iter = state.users.find(sender_addr);
    if (iter == state.users.end()) {
        // sender is not in the state, create new account
        // Only available when debug
        Account* acc = new Account;
        acc->balance = 0;
        acc->nonce = 0;
        acc->latest_SPV_block_number = 0;
        state.users[sender_addr] = acc;
    }

    // now take some of the deposit
    state.balances_for_settle_tx_fee += balance_for_tx_fee;
    state.routing_fee_waiting += state.routing_fee;

    // update user's balance
    unsigned long long balance_for_user = amount - balance_for_tx_fee - state.routing_fee;
    state.users[sender_addr]->balance += balance_for_user;

    // update total balances
    state.total_balances += balance_for_user;

    // update user's min_requested_block_number
    if (balance_for_user > 0) {
        state.users[sender_addr]->min_requested_block_number = block_number;
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
            printf("deal with new deposit tx -> user: %s / balance += %llu / tx fee += %llu\n", dr->sender_address.c_str(), balance_for_user, balance_for_tx_fee);
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
    state.routing_fee_confirmed += psti->pending_routing_fees;

    // print result
    if (doPrint) {
        // printf("deal with settle tx -> rouTEE owner got paid pending routing fee: %llu satoshi\n", psti->pending_routing_fees);
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

        keyID = tx_dest.keyID->ToString();
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

    state.block_number = block_number;
    state.block_hash[block_number] = block.GetBlockHeader().GetHash();

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

    state.block_number = block_number;
    state.block_hash[block_number] = block_header.GetHash();

    return NO_ERROR;
}

int ecall_get_current_block_number(int* current_block_number) {
    *current_block_number = state.block_number;

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
        encryption_result = make_encrypted_response(error_to_msg(ERR_DECRYPT_FAILED), session_key, encrypted_response, encrypted_response_len);
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
    const char* response_msg;
    if (operation == OP_GET_READY_FOR_DEPOSIT) {
        operation_result = secure_get_ready_for_deposit(decCommand, decCommandLen, sessionID, sessionID_len, decSignature, SGX_RSA3072_KEY_SIZE, response_msg);
    }
    else if (operation == OP_SETTLE_BALANCE) {
        operation_result = secure_settle_balance(decCommand, decCommandLen, sessionID, sessionID_len, decSignature, SGX_RSA3072_KEY_SIZE, response_msg);
    }
    else if (operation == OP_DO_MULTIHOP_PAYMENT) {
        operation_result = secure_do_multihop_payment(decCommand, decCommandLen, sessionID, sessionID_len, decSignature, SGX_RSA3072_KEY_SIZE, response_msg);
    }
    else if (operation == OP_ADD_USER) {
        operation_result = secure_add_user(decCommand, decCommandLen, sessionID, sessionID_len, decSignature, SGX_RSA3072_KEY_SIZE, response_msg);
    }
    else if (operation == OP_UPDATE_LATEST_SPV_BLOCK) {
        operation_result = secure_update_latest_SPV_block(decCommand, decCommandLen, sessionID, sessionID_len, decSignature, SGX_RSA3072_KEY_SIZE, response_msg);
    }
    else {
        // invalid opcode
        operation_result = ERR_INVALID_OP_CODE;
    }

    //
    // encrypt response
    //
    // @ Luke Park
    // mutex unlock
    sgx_thread_mutex_unlock(&state_mutex);

    // encrypt the response for client & return NO_ERROR to hide the ecall result from rouTEE host
    if (operation_result != -1) {
        response_msg = error_to_msg(operation_result);
    }
    encryption_result = make_encrypted_response(response_msg, session_key, encrypted_response, encrypted_response_len);
    if (encryption_result != NO_ERROR) {
        // TODO: if encryption failed, send rouTEE's signature for the failed cmd
        // to make client believe that the encrpytion really failed
        return ERR_ENCRYPT_FAILED;
    }

    // print result
    if (doPrint) {
        // printf("decrypted secure command: %s\n", decMessage);
        // printf("secure command result: %s\n", response_msg);
    }

    return NO_ERROR;
}

int ecall_make_owner_key(char* sealed_owner_private_key, int* sealed_key_len) {
    //
    // TODO: BITCOIN
    // make random bitcoin private key
    //
    // initialize ECC State for Bitcoin Library
    initializeECCState();
    // generate and print bitcoin addresses to be paid into by the user
    // generate new bitcoin pub/private key and address
    CKey key;
    key.MakeNewKey(true /* compressed */);
    CPubKey pubkey = key.GetPubKey();

    CKeyID keyid = pubkey.GetID();

    CBitcoinAddress address;
    address.Set(pubkey.GetID());

    std::string generated_address = address.ToString();
    std::string generated_public_key = HexStr(key.GetPubKey());
    std::string generated_private_key = CBitcoinSecret(key).ToString();

    printf("ecall_make_owner_key.generated_private_key: %s\n", generated_private_key.c_str());
    printf("ecall_make_owner_key.generated_public_key: %s\n", generated_public_key.c_str());
    printf("ecall_make_owner_key.generated_address: %s\n", generated_address.c_str());

    const char *random_private_key = generated_private_key.c_str();
    //char random_private_key[300] = "abcde"; // temp code
    // printf("random private key: %s\n", random_private_key);

    // seal the private key
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, (uint32_t)strlen(random_private_key));
    // printf("sealed_data_size: %d\n", sealed_data_size);
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
    const unsigned char *owner_private_key = reinterpret_cast<const unsigned char *>(state.owner_private_key.c_str());
    
    // initialize ECC State for Bitcoin Library
    initializeECCState();

    CKey key;
    key.Set(owner_private_key, owner_private_key + 32, true);
    CPubKey pubkey = key.GetPubKey();

    CBitcoinAddress address;
    address.Set(pubkey.GetID());

    std::string generated_address = address.ToString();
    std::string generated_public_key = HexStr(pubkey);
    printf("owner private key: %s\n", owner_private_key);
    state.owner_public_key = generated_public_key;
    state.owner_address = generated_address;

    state.block_number = 0;
    state.accumulated_tx_fee = 0;
    state.accumulated_tx_size = 0;

    printf("ecall_load_owner_key.generated_private_key: %s\n", CBitcoinSecret(key).ToString().c_str());
    printf("ecall_load_owner_key.generated_public_key: %s\n", generated_public_key.c_str());
    printf("ecall_load_owner_key.generated_address: %s\n", generated_address.c_str());

    // rouTEE host's public key for verification
    // state.users["host"] = ;
    // char byteArray[] = {}
    // std::string s(byteArray, sizeof(byteArray));

    // char *_input = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEpDe2hkjA3LeG8sjcGrBSfAIWxCXlIHQya9Apb7xR8Xjpe0bDWrPkrjZ38Dcqx0T3INM9UB+adVWE3hzduzR9qA==";
    // unsigned char *input = reinterpret_cast<unsigned char *>(_input);
    // unsigned char pubkey[88];
    // size_t pubkeylen;

    // ret = mbedtls_base64_decode( pubkey, 88, &pubkeylen, input, strlen(_input) );

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
    // // printf("owner private key: %s\n", state.owner_private_key.c_str());
    string state_str;
    state_str.assign(unsealed_state, unsealed_state + unsealed_state_length);
    state.from_string(state_str);

    // printf("success loading state!\n");

    return NO_ERROR;
}
