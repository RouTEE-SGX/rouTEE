#include <stdarg.h>
#include <stdio.h>

#include "Enclave.h"
#include "Enclave_t.h"

#include "channel.h"
#include "errors.h"

// user address to the user's channels
map< string, vector<Channel *> > addresses_to_channels;
vector<Channel *> channels;

// invoke OCall to display the enclave buffer to the terminal screen
void printf(const char *fmt, ...) {

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

int ecall_add_channel() {
    // temp code

    Channel *ch = new Channel;
    ch->addresses[0] = "0x1234";
    ch->addresses[1] = "0xabcd";
    ch->balances[0] = 10;
    ch->balances[1] = 20;
    ch->tx_id = "0x5678";
    ch->tx_index = 9;

    printf("new channel added: %s:%llu / %s:%llu\n", ch->addresses[0], ch->balances[0], ch->addresses[1], ch->balances[1]);

    channels.push_back(ch);
    return NO_ERROR;
}

int ecall_remove_channel(const char* target_ch_id, int ch_id_len) {
    string ch_to_remove = string(target_ch_id, ch_id_len);
    for (vector<Channel *>::iterator iter = channels.begin(); iter != channels.end(); iter++){
        if ((*iter)->get_id() == ch_to_remove) {
            printf("find target channels to erase: %s\n", (*iter)->to_string().c_str());
            channels.erase(iter);
            return NO_ERROR;
        }
    }

    // there is no channel whose id is "target_ch_id"
    return ERR_NO_CHANNEL;
}

void ecall_print_channels() {
    for (vector<Channel *>::iterator iter = channels.begin(); iter != channels.end(); iter++){
        printf("print channel %s info: %s\n", (*iter)->get_id().c_str(), (*iter)->to_string().c_str());
    }
    return;
}

void ecall_seal_channels() {
    // https://github.com/intel/linux-sgx/blob/master/SampleCode/SealUnseal/Enclave_Seal/Enclave_Seal.cpp
    // https://github.com/intel/linux-sgx/blob/master/SampleCode/SealUnseal/App/App.cpp
}

void ecall_unseal_channels() {
    
}
