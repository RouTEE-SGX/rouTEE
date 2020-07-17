#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <string>
#include <sstream>
#include <vector>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "network.h"
#include "../Enclave/errors.h"

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
    printf("What is this error? Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
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

// OCall function
void ocall_print_string(const char* str){
    // Proxy/Bridge will check the length and null-terminate 
    // the input string to prevent buffer overflow. 

    printf("%s", str);
}

// clean up the program and terminate it
void cleanup() {
    sgx_destroy_enclave(global_eid);
    exit(1);
}

// print error msg and end program
void error(const char* errmsg) {
    printf("%s\n", errmsg);
    cleanup();
}

// parse request as ecall function params
vector<string> parse_request(const char* request) {
    string req(request);
    stringstream ss(req);
    vector<string> params;
    string param;
    while (std::getline(ss, param, ' '))
        params.push_back(param);
    return params;
}

// add channel into the enclave
int add_channel(char* request) {

    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 3) {
        return ERR_INVALID_PARAMS;
    }
    string tx_id = params[1];
    unsigned int tx_index = strtoul(params[2].c_str(), NULL, 10);

    int ecall_return;
    int ecall_result = ecall_add_channel(global_eid, &ecall_return, tx_id.c_str(), tx_id.length(), tx_index);
    printf("ecall_add_channel() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_add_channel");
    }

    return ecall_return;
}

int print_channels() {
    int ecall_result = ecall_print_channels(global_eid);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_print_channels");
    }

    return NO_ERROR;
}

// remove channel from the enclave
int remove_channel(char* request) {

    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 2) {
        return ERR_INVALID_PARAMS;
    }
    string target_ch_id = params[1];

    // execute ecall
    int ecall_return;
    int ecall_result = ecall_remove_channel(global_eid, &ecall_return, target_ch_id.c_str(), target_ch_id.length());
    printf("ecall_remove_channel() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_remove_channel");
    }

    return ecall_return;
}

// do 1 to 1 single channel payment
int do_payment(char* request) {

    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 4) {
        return ERR_INVALID_PARAMS;
    }
    string channel_id = params[1];
    string sender_address = params[2];
    unsigned long long amount = strtoull(params[3].c_str(), NULL, 10);
    
    // execute ecall
    int ecall_return;
    int ecall_result = ecall_do_payment(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), sender_address.c_str(), sender_address.length(), amount);
    printf("ecall_do_payment() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_do_payment");
    }

    return ecall_return;
}

// set owner
int set_owner(char* request) {
    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 2) {
        return ERR_INVALID_PARAMS;
    }
    string owner_address = params[1];

    int ecall_return;
    int ecall_result = ecall_set_owner(global_eid, &ecall_return, owner_address.c_str(), owner_address.length());
    printf("ecall_set_owner() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_set_owner");
    }

    return ecall_return;
}

// set routing fee
int set_routing_fee(char* request) {
    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 2) {
        return ERR_INVALID_PARAMS;
    }
    unsigned long long fee = strtoull(params[1].c_str(), NULL, 10);

    int ecall_return;
    int ecall_result = ecall_set_routing_fee(global_eid, &ecall_return, fee);
    printf("ecall_set_routing_fee() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_set_routing_fee");
    }

    return ecall_return;
}

// set routing fee address
int set_routing_fee_address(char* request) {
    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 2) {
        return ERR_INVALID_PARAMS;
    }
    string fee_address = params[1];

    int ecall_return;
    int ecall_result = ecall_set_routing_fee_address(global_eid, &ecall_return, fee_address.c_str(), fee_address.length());
    printf("ecall_set_routing_fee_address() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_set_routing_fee_address");
    }

    return ecall_return;
}

// create channel with rouTEE
int create_channel(char* request) {
    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 3) {
        return ERR_INVALID_PARAMS;
    }
    string tx_id = params[1];
    unsigned int tx_index = strtoul(params[2].c_str(), NULL, 10);

    int ecall_return;
    int ecall_result = ecall_create_channel(global_eid, &ecall_return, tx_id.c_str(), tx_id.length(), tx_index);
    printf("ecall_create_channel() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_create_channel");
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

// settle my balance
int settle_balance(char* request) {
    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 2) {
        return ERR_INVALID_PARAMS;
    }
    string receiver_address = params[1];

    int ecall_return;
    int ecall_result = ecall_settle_balance(global_eid, &ecall_return, receiver_address.c_str(), receiver_address.length());
    printf("ecall_settle_balance() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_settle_balance");
    }

    return ecall_return;
}

// do multihop payment
int do_multihop_payment(char* request) {
    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 5) {
        return ERR_INVALID_PARAMS;
    }
    string sender_address = params[1];
    string receiver_address = params[2];
    unsigned long long amount = strtoul(params[3].c_str(), NULL, 10);
    unsigned long long fee = strtoul(params[4].c_str(), NULL, 10);

    int ecall_return;
    int ecall_result = ecall_do_multihop_payment(global_eid, &ecall_return, sender_address.c_str(), sender_address.length(), receiver_address.c_str(), receiver_address.length(), amount, fee);
    printf("ecall_do_multihop_payment() -> result:%d / return:%d\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_do_multihop_payment");
    }

    return ecall_return;
}

// get the balance of the user in this channel
const char* get_channel_balance(char* request) {

    // parse request as ecall function params
    vector<string> params = parse_request(request);
    if (params.size() != 3) {
        return error_to_msg(ERR_INVALID_PARAMS);
    }
    string channel_id = params[1];
    string user_address = params[2];
    
    // execute ecall
    unsigned long long ecall_return;
    int ecall_result = ecall_get_channel_balance(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), user_address.c_str(), user_address.length());
    printf("ecall_get_channel_balance() -> result:%d / return:%llu\n", ecall_result, ecall_return);
    if (ecall_result != SGX_SUCCESS) {
        error("ecall_do_payment");
    }

    if (ecall_return == MAX_UNSIGNED_LONG_LONG) {
        // return error message
        return "you cannot access to this channel's balance";
    }
    else {
        // return the balance as a string
        static char balance[30];
        snprintf(balance, 30, "%llu", ecall_return);
        return balance;
    }
}

// execute client's command
const char* execute_command(char* request) {
    char operation = request[0];
    int ecall_return;

    if (operation == OP_PUSH_A) {
        // sample template code
        printf("operation push A executed\n");
        ecall_return = NO_ERROR;
    }
    else if (operation == OP_ADD_CHANNEL) {
        printf("add channel operation executed\n");
        ecall_return = add_channel(request);
    }
    else if (operation == OP_PRINT_CHANNELS) {
        printf("print channels executed\n");
        ecall_return = print_channels();
    }
    else if (operation == OP_REMOVE_CHANNEL) {
        printf("remove channels executed\n");
        ecall_return = remove_channel(request);
    }
    else if (operation == OP_DO_PAYMENT) {
        printf("do payment executed\n");
        ecall_return = do_payment(request);
    }
    else if (operation == OP_SET_OWNER) {
        printf("set owner executed\n");
        ecall_return = set_owner(request);
    }
    else if (operation == OP_SET_ROUTING_FEE) {
        printf("set routing fee executed\n");
        ecall_return = set_routing_fee(request);
    }
    else if (operation == OP_SET_ROUTING_FEE_ADDRESS) {
        printf("set routing fee address executed\n");
        ecall_return = set_routing_fee_address(request);
    }
    else if (operation == OP_CREATE_CHANNEL) {
        printf("create channel executed\n");
        ecall_return = create_channel(request);
    }
    else if (operation == OP_PRINT_STATE) {
        printf("print state executed\n");
        ecall_return = print_state();
    }
    else if (operation == OP_SETTLE_BALANCE) {
        printf("settle balance executed\n");
        ecall_return = settle_balance(request);
    }
    else if (operation == OP_DO_MULTIHOP_PAYMENT) {
        printf("do multihop payment executed\n");
        ecall_return = do_multihop_payment(request);
    }
    else if (operation == OP_GET_CHANNEL_BALANCE) {
        // tricky code to return the balance value
        printf("get channel balance executed\n");
        return get_channel_balance(request);
    }
    else{
        // wrong op_code
        printf("this op code doesn't exist\n");
        ecall_return = ERR_INVALID_OP_CODE; // actually this is not ecall return value, ecall doesn't happen
    }

    return error_to_msg(ecall_return);
}

// application entry point
int SGX_CDECL main(int argc, char* argv[]){

    // not used vars -> I just dont care, ignore these
    (void)(argc);
    (void)(argv);

    // initialize the enclave
    if (initialize_enclave() < 0){
        // failed to initialize enclave
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    // run socket server to get commands
    int opt = TRUE;
    int master_socket, addrlen, new_socket, client_socket[30], activity, read_len, sd;
    int max_sd;
    struct sockaddr_in address;
    char request[MAX_MSG_SIZE+1];  // data buffer of 1K
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
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Listener on port %d \n", SERVER_PORT);

    // try to specify maximum of 3 pending connections for the master socket
    if (listen(master_socket, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // accept the incoming connection
    addrlen = sizeof(address);
    puts("Waiting for connections ...");
    
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
            printf("select error");
        }
        
        // If something happened on the master socket, then its an incoming connection
        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }
            
            // inform user of socket number - used in send and receive commands
            printf("New connection , socket fd is %d , ip is : %s , port : %d\n" , new_socket , inet_ntoa(address.sin_addr) , ntohs (address.sin_port));

            // add new socket to array of sockets
            for (int i = 0; i < MAX_CLIENTS; i++) {
                // if position is empty
                if(client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    printf("Adding to list of sockets as %d\n" , i);
                    break;
                }
            }

        }
        
        // else its some IO operation on some other socket
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];
            
            if (FD_ISSET(sd , &readfds)) {
                // Check if it was for closing, and also read the incoming message
                if ((read_len = read(sd, request, MAX_MSG_SIZE)) == 0) {
                    // Somebody disconnected, get his details and print
                    getpeername(sd , (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    printf("Host disconnected, ip %s, port %d \n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                    // Close the socket and mark as 0 in list for reuse
                    close(sd);
                    client_socket[i] = 0;
                }
                // Echo back the message that came in
                else {
                    // set the string terminating NULL byte on the end of the data read
                    request[read_len] = '\0';
                    printf("client %d says: %s, (len: %d)\n", sd, request, read_len);

                    // execute client's command
                    response = execute_command(request);
                    printf("execution result: %s\n\n", response);

                    // send result to the client
                    send(sd, response, strlen(response), 0);
                }
            }
        }

    }

    // destroy the enclave
    sgx_destroy_enclave(global_eid);

    printf("terminate the App\n");
    return 0;
}
