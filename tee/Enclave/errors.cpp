#include "errors.h"

const char* error_to_msg(int err) {
    switch(err) {
        case NO_ERROR:
            return "SUCCESS";
        case ERR_INVALID_OP_CODE:
            return "this op code doesn't exist";
        case ERR_INVALID_CHANNEL:
            return "invalid channel";
        case ERR_NO_CHANNEL:
            return "there is no channel like that";
        case ERR_INVALID_PARAMS:
            return "invalid op params";
        case ERR_INVALID_USER:
            return "the user is not in that channel";
        case ERR_NOT_ENOUGH_BALANCE:
            return "the user has not enough balance";
        case ERR_ALREADY_EXIST_CHANNEL:
            return "this channel is already added before";
        case ERR_INVALID_RECEIVER:
            return "your tx didn't send BTC to the owner address";
        case ERR_NOT_ENOUGH_FEE:
            return "need higher routing fee";
        case ERR_SGX_ERROR_UNEXPECTED:
            return "sgx error: SGX_ERROR_UNEXPECTED";
        case ERR_SEAL_FAILED:
            return "sealing failed";
        case ERR_UNSEAL_FAILED:
            return "unsealing failed";
        case ERR_DECRYPT_FAILED:
            return "AES-GCM decryption failed";
        case ERR_ENCRYPT_FAILED:
            return "AES-GCM encryption failed";
        case ERR_NO_RECEIVER:
            return "payment receiver not exists in state";
        case ERR_RECEIVER_NOT_READY:
            return "payment receiver has low latest SPV block number";
        case ERR_ADDRESS_NOT_EXIST:
            return "this address is not in the state";
        default:
            return "wrong error index";
    }
}
