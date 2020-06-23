#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>

#define MAX_PATH FILENAME_MAX   // FILENAME_MAX: already defined in stdio.h

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
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
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int token_updated = 0;

    // step 1: try to retrieve the launch token saved by last transaction
    // if there is no token, then create a new one

    // try to get the token saved in $HOME
    const char *home_dir = getpwuid(getuid())->pw_dir;

    // compose the token_path
    if (home_dir != NULL && (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH){
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
void ocall_print_string(const char *str){
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
void error(const char *errmsg) {
    printf("%s\n", errmsg);
    cleanup();
}

// application entry point
int SGX_CDECL main(int argc, char *argv[]){

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

    // ECall
    // printf_helloworld(global_eid);

    // run socket server to get command
    
    int server_socket;
    int client_socket;

    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_size;

    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1){
        error("socket error");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1) {
        error("bind error");
    }

    if (listen(server_socket, 10) == -1) {
        error("listen error");
    }

    char client_msg[20];
    while (true) {
        printf("server listening...\n");
        client_addr_size = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr*) &client_addr, &client_addr_size);
        if (client_socket == -1) {
            error("accept error");
        }
        
        int client_msg_size = recv(client_socket, client_msg, MAX_MSG_SIZE, 0);
        printf("client says:%s\n", client_msg);

        if (client_msg[0] == 'q') {
            break;
        }
    }

    // destroy the enclave
    sgx_destroy_enclave(global_eid);

    return 0;
}


