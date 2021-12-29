#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <string>
#include <sstream>
// #include <vector>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <time.h>

#include "sgx_urts.h"
#include "routee.h"
#include "routee_u.h"
#include "../Enclave/network.h"
#include "../Enclave/errors.h"

// @ Luke Park
// Ref. https://modoocode.com/285
#include <future>
#include <thread>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <mutex>
#include <queue>
#include <vector>

#include "openssl/evp.h"
#include "openssl/pem.h"

#include "mbedtls/pem.h"

#define SGX_RSA3072_KEY_SIZE 384

namespace ThreadPool {

class ThreadPool {
    public:
        ThreadPool(size_t num_threads);
        ~ThreadPool();
        int workCount = 0;
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point end_time;

    template <class F, class... Args>
    std::future<typename std::result_of<F(Args...)>::type> EnqueueJob(
        F&& f, Args&&... args);

    private:
        size_t num_threads_;
        std::vector<std::thread> worker_threads_; // workers (CPUs)
        std::queue<std::function<void()>> jobs_;  // jobs (Threads)
        std::condition_variable cv_job_q_;
        std::mutex m_job_q_;

    bool stop_all;

    void WorkerThread();
};

ThreadPool::ThreadPool(size_t num_threads)
    : num_threads_(num_threads), stop_all(false) {

    worker_threads_.reserve(num_threads_);
    for (size_t i = 0; i < num_threads_; ++i) {
        worker_threads_.emplace_back([this]() { this->WorkerThread(); });
    }
}

void ThreadPool::WorkerThread() {
    if (workCount - NEGLECT_COUNT >= 0) {
        start_time = std::chrono::system_clock::now();
    }
    while (true) {
        std::unique_lock<std::mutex> lock(m_job_q_);
        cv_job_q_.wait(lock, [this]() { return !this->jobs_.empty() || stop_all; });
        if (stop_all && this->jobs_.empty()) { return; }

        std::function<void()> job = std::move(jobs_.front());
        jobs_.pop();
        lock.unlock();


        job();  // Run

        workCount++;

        if (workCount % PRINT_EPOCH == 0) {
            end_time = std::chrono::system_clock::now();
            std::chrono::milliseconds milli = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            std::cout << "work count: " << workCount << "\t" << milli.count() << " ms" << std::endl;
        }
    }
}

ThreadPool::~ThreadPool() {
    stop_all = true;
    cv_job_q_.notify_all();

    for (auto& t : worker_threads_) {
        t.join();
    }
}

template <class F, class... Args>
std::future<typename std::result_of<F(Args...)>::type> ThreadPool::EnqueueJob(
    F&& f, Args&&... args) {
    if (stop_all) { throw std::runtime_error("Stop all ThreadPool"); }

    using return_type = typename std::result_of<F(Args...)>::type;
    auto job = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));
    std::future<return_type> job_result_future = job->get_future();
    {
        std::lock_guard<std::mutex> lock(m_job_q_);
        jobs_.push([job]() { (*job)(); });
    }
    cv_job_q_.notify_one();

    return job_result_future;
}

}
// namespace ThreadPool

using std::string;
using std::vector;
using std::stringstream;

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char* msg;
    const char* sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

// print sgx error message on terminal
void print_error_message(sgx_status_t ret){
    size_t index = 0;
    size_t total = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (index = 0; index < total; index++){
        if (ret == sgx_errlist[index].err){
            // find matching error in the sgx_errlist. print it
            if (sgx_errlist[index].sug != NULL){
                printf("Info: %s\n", sgx_errlist[index].sug);
            }
            printf("Error: %s\n", sgx_errlist[index].msg);
            return;
        }
    }

    // cannot find matching error in the sgx_errlist
    // printf("What is this error? Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

// initialize the enclave
// step 1: try to retrieve the launch token saved by last transaction
// step 2: call sgx_create_enclave to initialize an enclave instance
// step 3: save the launch token if it is updated
int initialize_enclave(void){
    char token_path[FILENAME_MAX] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int token_updated = 0;

    // step 1: try to retrieve the launch token saved by last transaction
    // if there is no token, then create a new one

    // try to get the token saved in $HOME
    const char* home_dir = getpwuid(getuid())->pw_dir;

    // compose the token_path
    if (home_dir != NULL && (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= FILENAME_MAX){
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else{
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    // try to retrieve the launch token from token_path
    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL){
        // failed to open the launch token file
        printf("Warning: Failed to open the launch token file \"%s\".\n", token_path);
    }
    // try to create new launch token file
    if ((fp = fopen(token_path, "wb")) == NULL){
        // failed to create a launch token file
        printf("Warning: Failed to create a launch token file \"%s\".\n", token_path);
    }
    if (fp != NULL) {
        // read the token from saved file
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)){
            // if token is invalid, clear the buffer
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    // step 2: call sgx_create_enclave to initialize an enclave instance
    // debugging tip: set SGX_DEBUG_FLAG to 1
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS){
        // fail to create enclave
        print_error_message(ret); // check error conditions for loading enclave
        if (fp != NULL){
            fclose(fp);
        }
        return -1;
    }

    // step 3: save the launch token if it is updated
    if (token_updated == FALSE || fp == NULL){
        // token is not updated || file handler is invalid -> do not save token file
        if (fp != NULL){
            fclose(fp);
        }
        return 0;
    }

    // token is updated -> reopen the token file to save the changed launch token
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL){
        return 0;   // fail to save but success creating enclave, it's ok
    }
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t)){
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    }
    fclose(fp);
    return 0;   // fail to save but success creating enclave, it's ok
}

/*
// OCall function
void ocall_print_string(const char* str){
    // Proxy/Bridge will check the length and null-terminate 
    // the input string to prevent buffer overflow. 

    // printf("%s", str);
}
*/

// clean up the program and terminate it
void cleanup() {
    printf("terminate the app\n");
    sgx_destroy_enclave(global_eid);
    exit(1);
}

// print error msg and end program
void error(const char* errmsg) {
    printf("error occurred: %s\n", errmsg);
    cleanup();
}

// load encrypted state from a file
void load_state() {

    // if there is no saved state, just terminate
    struct stat buffer;
    char* sealed_state;
    int sealed_state_len;
    if (stat (STATE_FILENAME, &buffer) != 0) {
        // printf("there is no saved state. just start rouTEE\n");
        return;
    } else {
        // load sealed state from the file
        // printf("read sealed state from the file\n");
        std::ifstream in(STATE_FILENAME);
        std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        sealed_state_len = contents.length();
        sealed_state = new char[sealed_state_len];
        memcpy(sealed_state, contents.c_str(), sealed_state_len);
    }

    // load state
    // printf("load state\n");
    int ecall_return;
    int ecall_result = ecall_load_state(global_eid, &ecall_return, sealed_state, sealed_state_len);
    // printf("ecall_load_state() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_load_state");
    }
    if (ecall_return != 0) {
        error(error_to_msg(ecall_return).c_str());
    }

    delete[] sealed_state;
    // printf("load state from a file\n");
    return;
}

// set owner key inside the enclave
void set_owner() {
    
    // if there is no owner key, create new one
    struct stat buffer;
    char sealed_owner_private_key[MAX_SEALED_KEY_LENGTH];
    if (stat (OWNER_KEY_FILENAME, &buffer) != 0) {
        // make new private key
        // printf("generate new owner key\n");
        int ecall_return;
        int sealed_key_len;
        int ecall_result = ecall_make_owner_key(global_eid, &ecall_return, sealed_owner_private_key, &sealed_key_len);
        // printf("ecall_make_owner_key() -> result:%d / return:%d\n", ecall_result, ecall_return);
        if (ecall_result != SGX_SUCCESS) {
            error("ecall_make_owner_key");
        }

        // save sealed owner private key as a file
        std::ofstream out(OWNER_KEY_FILENAME);
        if (!out){
            error("cannot open file");
        }
        // out.write(sealed_owner_private_key, strlen(sealed_owner_private_key));
        out.write(sealed_owner_private_key, sealed_key_len);
        out.close();
    } else {
        // load sealed private key from the file
        // printf("read sealed owner key from the file");
        std::ifstream in(OWNER_KEY_FILENAME);
        std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        memcpy(sealed_owner_private_key, contents.c_str(), contents.length());
    }

    // load host's public key for authentication
    EVP_PKEY* pPubKey  = NULL;
    FILE* pFile = NULL;

    if((pFile = fopen("./client/key/public_key_host.pem","rt")) && 
        (pPubKey = PEM_read_PUBKEY(pFile,NULL,NULL,NULL)))
    {
        printf("Public key read.\n");
    }
    else
    {
        printf("Cannot read \"pubkey.pem\".\n");
    }
    
    // load owner key's address
    // printf("load owner key\n");
    int ecall_return;
    int ecall_result = ecall_load_owner_key(global_eid, &ecall_return, sealed_owner_private_key, sizeof(sealed_owner_private_key));
    // printf("ecall_load_owner_key() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_load_owner_key");
    }
    if (ecall_return != 0) {
        error(error_to_msg(ecall_return).c_str());
    }

    // printf("set_owner() finished\n");
}

// parse request as ecall function params (delimiter: ' ')
vector<string> parse_request(const char* request) {
    string req(request);
    stringstream ss(req);
    vector<string> params;
    string param;
    while (std::getline(ss, param, ' '))
        params.push_back(param);
    return params;
}

// set routing fee
int set_routing_fee(char* request, int request_len) {
    int signature_len = SGX_RSA3072_KEY_SIZE;
    int command_len = request_len - signature_len - 1;
    char command[command_len + 1];
    strncpy(command, request, (size_t) command_len);
    command[command_len] = '\0';
    // parse request as ecall function params
    /*
    vector<string> params = parse_request(command);
    if (params.size() != 2) {
        printf("param size: %d\n", (int)params.size());
        return ERR_INVALID_PARAMS;
    }
    unsigned long long fee = strtoull(params[1].c_str(), NULL, 10);
    */
    const char *signatureMessage = request + command_len + 1;
    // string signature = params[2];

    // size_t n;
    // unsigned char* buf;
    // int ret = mbedtls_pk_load_file( "../client/key/public_key_alice", &buf, &n );
    // printf("App/set_routing_fee ret: %d\n\n", ret);
    printf("App/strlen(command): %s, %d\n\n", command, command_len);

    int ecall_return;
    int ecall_result = ecall_set_routing_fee(global_eid, &ecall_return, command, command_len, signatureMessage, signature_len);
    // printf("ecall_set_routing_fee() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_set_routing_fee");
    }

    return ecall_return;
}

// set routing fee address
int set_routing_fee_address(char* request, int request_len) {
    // // parse request as ecall function params
    // vector<string> params = parse_request(request);
    // if (params.size() != 3) {
    //     return ERR_INVALID_PARAMS;
    // }
    // string fee_address = params[1];
    // string signature = params[2];

    int signature_len = SGX_RSA3072_KEY_SIZE;
    int command_len = request_len - signature_len - 1;
    char command[command_len + 1];
    strncpy(command, request, (size_t) command_len);
    command[command_len] = '\0';
    std::cout << command << std::endl;

    const char *signatureMessage = request + command_len + 1;

    int ecall_return;
    int ecall_result = ecall_set_routing_fee_address(global_eid, &ecall_return, command, command_len, signatureMessage, signature_len);
    // printf("ecall_set_routing_fee_address() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_set_routing_fee_address");
    }

    return ecall_return;
}

// set bitcoin-cli path
const string base_cmd = "~/bitcoin-0.20.1/bin/bitcoin-cli ";
// option for bitcoin network
const string mode = "-regtest -rpcport=1234 -rpcuser=node -rpcpassword=0000 ";

std::string exec(const char* cmd) {
    char buffer[256];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL){
                result += buffer;
            }
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

std::string get_block_hash(std::string block_number){
    std::string rpc("getblockhash ");
    rpc = base_cmd + mode + rpc + block_number;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    while (pout.find ("\n") != std::string::npos )
    {
        pout.erase (pout.find ("\n"), 1 );
    }
    return pout;
}

std::string get_best_block_hash(){
    std::string rpc("getbestblockhash");
    rpc = base_cmd + mode + rpc;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    while (pout.find ("\n") != std::string::npos )
    {
        pout.erase (pout.find ("\n"), 1 );
    }
    return pout;
}

std::string get_hexed_block(std::string hashval){
    std::string rpc("getblock ");
    std::string verbose(" false");
    rpc = base_cmd + mode + rpc + hashval + verbose;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    std::stringstream ss(pout);
    std::string line;
    ss >> line;
    return line;
}

std::string get_hexed_block_header(std::string hashval){
    std::string rpc("getblockheader ");
    std::string verbose(" false");
    rpc = base_cmd + mode + rpc + hashval + verbose;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    std::stringstream ss(pout);
    std::string line;
    ss >> line;
    return line;
}

std::string get_block_count(){
    std::string rpc("getblockcount");
    rpc = base_cmd + mode + rpc;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    while (pout.find ("\n") != std::string::npos )
    {
        pout.erase (pout.find ("\n"), 1 );
    }
    return pout;
}

// insert block
int insert_block(char* request, int request_len) {
    vector<string> params = parse_request(request);

    if (params.size() < 3) {
        printf("no sufficient params!\n");
        return ERR_INVALID_PARAMS;
    }
    string block_number = params[1];
    string signature = params[2];

    string block_hash = get_block_hash(block_number);
    if (block_hash.compare("false") == 0) {
        printf("invalid block number insertion\n");
        return ERR_INVALID_PARAMS;
    }

    // string block_hash = get_best_block_hash();
    string hexed_block = get_hexed_block(block_hash);

    // std::cout << get_block_hash(block_number) << std::endl;
    // std::cout << get_hexed_block(block_hash) << std::endl;

    int ecall_return;
    int ecall_result = ecall_insert_block(global_eid, &ecall_return, std::stoi(block_number), hexed_block.c_str(), hexed_block.length());
    // printf("ecall_insert_block() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_insert_block");
    }

    return ecall_return;
}

int insert_block_header(char* request, int request_len) {
    vector<string> params = parse_request(request);

    if (params.size() < 3) {
        printf("no sufficient params!\n");
        return ERR_INVALID_PARAMS;
    }
    string block_number = params[1];
    string signature = params[2];

    string block_hash = get_block_hash(block_number);
    if (block_hash.compare("false") == 0) {
        printf("invalid block number insertion\n");
        return ERR_INVALID_PARAMS;
    }

    string hexed_block_header = get_hexed_block_header(block_hash);
    // std::cout << hexed_block_header << std::endl;

    int ecall_return;
    int ecall_result = ecall_insert_block_header(global_eid, &ecall_return, std::stoi(block_number), hexed_block_header.c_str(), hexed_block_header.length());
    // printf("ecall_insert_block() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_insert_block_header");
    }

    return ecall_return;
}

int sync_with_blockchain(char* request, int request_len) {
    vector<string> params = parse_request(request);

    if (params.size() < 2) {
        printf("no sufficient params!\n");
        return ERR_INVALID_PARAMS;
    }
    int block_end = std::stoi(params[1]);

    int current_block_number;

    int ecall_return;
    int ecall_result = ecall_get_current_block_number(global_eid, &ecall_return, &current_block_number);
    // printf("ecall_sync_blockchain() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_get_current_block_number");
        return ecall_return;
    }

    int block_height = std::stoi(get_block_count());
    block_height = block_end < block_height? block_end : block_height;
    printf("inserted block number: %d\n", block_height - current_block_number);
    for (int i = current_block_number + 1; i <= block_height; i++) {
        string request_str = "d " + std::to_string(i) + " host";
        // For debugging
        ecall_return = insert_block((char*) request_str.c_str(), request_str.length());
        if (ecall_return != NO_ERROR) {
            printf("something went wrong while syncing with blockchain at %d\n", i);
            break;
        }
    }

    return ecall_return;
}

// settle request for routing fee
int settle_routing_fee(char* request, int request_len) {
    // // parse request as ecall function params
    // vector<string> params = parse_request(request);
    // if (params.size() != 3) {
    //     return ERR_INVALID_PARAMS;
    // }
    // unsigned long long amount = strtoull(params[1].c_str(), NULL, 10);
    // string signature = params[2];

    int signature_len = SGX_RSA3072_KEY_SIZE;
    int command_len = request_len - signature_len - 1;
    char command[command_len + 1];
    strncpy(command, request, (size_t) command_len);
    command[command_len] = '\0';

    const char *signatureMessage = request + command_len + 1;

    int ecall_return;
    int ecall_result = ecall_settle_routing_fee(global_eid, &ecall_return, command, command_len, signatureMessage, signature_len);
    // printf("ecall_settle_routing_fee() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_settle_routing_fee");
    }

    return ecall_return;
}

// print state
int print_state() {
    int ecall_result = ecall_print_state(global_eid);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_print_state");
    }

    return NO_ERROR;
}

// make on-chain settle tx
int make_settle_transaction() {
    int ecall_return;
    char settle_transaction[MAX_TX_SIZE];
    int settle_tx_len;
    int ecall_result = ecall_make_settle_transaction(global_eid, &ecall_return, settle_transaction, &settle_tx_len);
    // printf("ecall_make_settle_transaction() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_make_settle_transaction");
    }

    // 
    // TODO: BITCOIN
    // if successed to make tx, broadcast it
    // 

    return ecall_return;
}

// insert deposit tx (for debugging)
int insert_deposit_tx(char* request, int request_len) {
    int signature_len = SGX_RSA3072_KEY_SIZE;
    int command_len = request_len - signature_len - 1;
    char command[command_len + 1];
    strncpy(command, request, (size_t) command_len);
    command[command_len] = '\0';
    // parse request as ecall function params
    /*
    vector<string> params = parse_request(command);
    if (params.size() != 2) {
        printf("param size: %d\n", (int)params.size());
        return ERR_INVALID_PARAMS;
    }
    unsigned long long fee = strtoull(params[1].c_str(), NULL, 10);
    */
    const char *signatureMessage = request + command_len + 1;

    // parse request as ecall function params
    vector<string> params = parse_request(command);
    // if (params.size() != 6) {
    //     return ERR_INVALID_PARAMS;
    // }
    // string sender_address = params[1];
    // string txid = params[2];
    // int tx_index = stoi(params[3]);
    // unsigned long long amount = strtoull(params[4].c_str(), NULL, 10);
    // unsigned long long block_number = strtoull(params[5].c_str(), NULL, 10);
    string sender_address = params[1];
    int tx_index = stoi(params[2]);
    unsigned long long amount = strtoull(params[3].c_str(), NULL, 10);
    unsigned long long block_number = strtoull(params[4].c_str(), NULL, 10);
    // For dubugging (sjkim)
    string script = "76a914acd4a257ec3b3593d0137d640a48ed52b3ed998f88ac";

    int ecall_result = deal_with_deposit_tx(global_eid, sender_address.c_str(), sender_address.length(), signatureMessage, signature_len, tx_index, script.c_str(), script.length(), amount, block_number);
    // printf("deal_with_deposit_tx() -> result:%d\n", ecall_result);
    if (ecall_result != SGX_SUCCESS) {
        error("deal_with_deposit_tx");
    }

    return NO_ERROR;
}

// insert settle tx (for debugging)
int insert_settle_tx(char* request, int request_len) {
    int ecall_result = deal_with_settlement_tx(global_eid);
    // printf("deal_with_settlement_tx() -> result:%d\n", ecall_result);
    if (ecall_result != SGX_SUCCESS) {
        error("deal_with_settlement_tx");
    }

    return NO_ERROR;
}

// save sealed current state as a file
void seal_state() {

    // if there is no owner key, create new one
    struct stat buffer;
    char* sealed_state = new char[MAX_SEALED_DATA_LENGTH];

    // get sealed current state
    int ecall_return;
    int sealed_state_len;
    int ecall_result = ecall_seal_state(global_eid, &ecall_return, sealed_state, &sealed_state_len);
    // printf("ecall_seal_state() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_seal_state");
    }

    // save sealed state as a file
    std::ofstream out(STATE_FILENAME);
    if (!out){
        error("cannot open file");
    }
    out.write(sealed_state, sealed_state_len);
    out.close();

    delete[] sealed_state;
    // printf("seal_state() success!\n");
}

// give encrypted cmd to rouTEE
void secure_command(char* request, int request_len, int sd) {
    // buffer for encrypted response from ecall
    char encrypted_response[MAX_ENCRYPTED_RESPONSE_LENGTH];
    int encrypted_response_len;

    // parse request as ecall function params
    vector<string> params = parse_request(request);
    string sessionID = params[1];
    char* encrypted_cmd = request+3+sessionID.length(); // 3+sessionID.length() means length of this string: "p sessionID " (not encrypted data)

    // request_len is required because when encrypted_cmd contains '0', then this '0' is accepted as '\0': the end of the string
    // so to know the correct request length, we need this request_len param
    int ecall_return;
    int ecall_result = ecall_secure_command(global_eid, &ecall_return, sessionID.c_str(), sessionID.length(), encrypted_cmd, request_len-3-sessionID.length(), encrypted_response, &encrypted_response_len);
    // printf("ecall_secure_command() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_secure_command");
    }

    // save state inside the enclave
    if (STATE_SAVE_EPOCH != 0 && state_save_counter % STATE_SAVE_EPOCH == 0) {
        seal_state();
    }
    state_save_counter++;

    // send response to client
    // int error_index = ecall_return;
    if (ecall_return != NO_ERROR) {
        // encryption faild in secure_command, just send plain response msg
        printf("failed encryption!\n");
        const char* response = "failed encryption in secure_command()";
        send(sd, response, strlen(response), 0);
    }
    else {
        // send encrypted response to the client
        send(sd, encrypted_response, encrypted_response_len, 0);
    }

    // @ Luke Park
    // sleep(1);
}

// execute client's command
const char* execute_command(char* request, int request_len) {
    char operation = request[0];
    int ecall_return;

    if (operation == OP_PUSH_A) {
        // sample template code
        // printf("operation push A executed\n");
        ecall_return = NO_ERROR;
    }
    else if (operation == OP_SET_ROUTING_FEE) {
        // printf("set routing fee executed\n");
        ecall_return = set_routing_fee(request, request_len);
    }
    else if (operation == OP_SET_ROUTING_FEE_ADDRESS) {
        // printf("set routing fee address executed\n");
        ecall_return = set_routing_fee_address(request, request_len);
    }
    else if (operation == OP_PRINT_STATE) {
        // printf("print state executed\n");
        ecall_return = print_state();
    }
    else if (operation == OP_MAKE_SETTLE_TRANSACTION) {
        // printf("make settle transaction executed\n");
        ecall_return = make_settle_transaction();
    }
    else if (operation == OP_INSERT_BLOCK) {
        // printf("insert block executed\n");
        ecall_return = insert_block(request, request_len);
    }
    else if (operation == OP_INSERT_BLOCK_HEADER) {
        // printf("insert block executed\n");
        ecall_return = insert_block_header(request, request_len);
    }
    else if (operation == OP_SYNC_WITH_BLOCKCHAIN) {
        // printf("sync blockchain executed\n");
        ecall_return = sync_with_blockchain(request, request_len);
    }
    else if (operation == OP_SETTLE_ROUTING_FEE) {
        // printf("settle routing fee executed\n");
        ecall_return = settle_routing_fee(request, request_len);
    }
    else if (operation == OP_INSERT_DEPOSIT_TX) {
        // printf("insert deposit tx executed\n");
        ecall_return = insert_deposit_tx(request, request_len);
    }
    else if (operation == OP_INSERT_SETTLE_TX) {
        // printf("insert settle tx executed\n");
        ecall_return = insert_settle_tx(request, request_len);
    }
    else if (operation == OP_SEAL_STATE) {
        printf("seal state executed\n");
        std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
        seal_state();
        std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
        std::chrono::milliseconds milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::chrono::microseconds micro = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Elapsed time for state sealing: " << micro.count() << " us (" << milli.count() << " ms)" << std::endl;

        ecall_return = NO_ERROR;
    }
    else{
        // wrong op_code
        // printf("this op code doesn't exist\n");
        ecall_return = ERR_INVALID_OP_CODE; // actually this is not ecall return value, ecall doesn't happen
    }

    // save state inside the enclave
    if (STATE_SAVE_EPOCH != 0 && state_save_counter % STATE_SAVE_EPOCH == 0) {
        seal_state();
    }
    state_save_counter++;

    return error_to_msg(ecall_return).c_str();
}

// application entry point
int SGX_CDECL main(int argc, char* argv[]){

    // not used vars -> I just dont care, ignore these
    (void)(argc);
    (void)(argv);

    // initialize the enclave
    if (initialize_enclave() < 0){
        // failed to initialize enclave
        // printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    // if there is a saved state, load it
    printf("unseal state executed\n");
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    load_state();
    std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
    std::chrono::milliseconds milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::chrono::microseconds micro = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Elapsed time for state unsealing: " << micro.count() << " us (" << milli.count() << " ms)" << std::endl;

    // set owner key
    // TODO: merge this function with load_state()
    set_owner();

    // run socket server to get commands
    int opt = TRUE;
    int master_socket, addrlen, new_socket, client_socket[MAX_CLIENTS], activity, read_len, sd;
    int max_sd;
    struct sockaddr_in address;
    const char* response;

    // set of socket descriptors
    fd_set readfds;
    
    // initialise all client_socket[] to 0 so not checked
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_socket[i] = 0;
    }

    // create a master socket
    if((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // set master socket to allow multiple connections,
    // this is just a good habit, it will work without this
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0 ) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    // type of socket created
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(SERVER_IP);
    address.sin_port = htons(SERVER_PORT);

    // bind the socket to SERVER_IP:SERVER_PORT
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed (set SERVER_IP or SERVER_PORT in App/routee.h correctly)");
        exit(EXIT_FAILURE);
    }
    // printf("Listener on port %d \n", SERVER_PORT);

    // try to specify maximum of 3 pending connections for the master socket
    if (listen(master_socket, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // accept the incoming connection
    addrlen = sizeof(address);
    puts("Waiting for connections ...");

    // @ Luke Park
    // num of threads
    ThreadPool::ThreadPool pool(4);

    while(TRUE) {
        // clear the socket set
        FD_ZERO(&readfds);

        // add master socket to set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        // add child sockets to set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            // socket descriptor
            sd = client_socket[i];
            
            // if valid socket descriptor then add to read list
            if(sd > 0) {
                FD_SET(sd , &readfds);
            }
            
            // highest file descriptor number, need it for the select function  
            if(sd > max_sd) {
                max_sd = sd;
            }
            
        }

        // wait for an activity on one of the sockets, timeout is NULL, so wait indefinitely  
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);   

        if ((activity < 0) && (errno != EINTR)) {
            // printf("select error");
        }
        
        // If something happened on the master socket, then its an incoming connection
        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }
            
            // inform user of socket number - used in send and receive commands
            // printf("New connection , socket fd is %d , ip is : %s , port : %d\n" , new_socket , inet_ntoa(address.sin_addr) , ntohs (address.sin_port));

            // add new socket to array of sockets
            for (int i = 0; i < MAX_CLIENTS; i++) {
                // if position is empty
                if(client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    // printf("Adding to list of sockets as %d\n" , i);
                    break;
                }
            }

        }

        char requests[MAX_CLIENTS][MAX_MSG_SIZE+1];  // data buffer of 1K


        // else its some IO operation on some other socket
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            
            if (FD_ISSET(sd , &readfds)) {
                // Check if it was for closing, and also read the incoming message
                if ((read_len = read(sd, requests[i], MAX_MSG_SIZE)) == 0) {
                    // Somebody disconnected, get his details and print
                    getpeername(sd , (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    // printf("Host disconnected, ip %s, port %d \n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                    // Close the socket and mark as 0 in list for reuse
                    close(sd);
                    client_socket[i] = 0;
                }
                // Echo back the message that came in
                else {
                    // set the string terminating NULL byte on the end of the data read
                    requests[i][read_len] = '\0';
                    // printf("client %d says: %s, (len: %d)\n", sd, request, read_len);

                    // execute client's command
                    char operation = requests[i][0];
                    if (operation == OP_SECURE_COMMAND) {
                        // @ Luke Park
                        // execute client's command      
                  
                        // /* Async */
                        // // std::async(std::launch::async, secure_command, request, read_len, sd);

                        /* ThreadPool */
                        pool.EnqueueJob(secure_command, requests[i], read_len, sd);

                        /* Sync */
                        // secure_command(request, read_len, sd);

                    }
                    else {
                        // execute client's command
                        response = execute_command(requests[i], read_len);
                        
                        // send result to the client
                        send(sd, response, strlen(response), 0);
                    }
                    // printf("execution result: %s\n\n", response);
                }
            }
        }

    }

    // destroy the enclave
    sgx_destroy_enclave(global_eid);

    // printf("terminate the App\n");
    return 0;
}
