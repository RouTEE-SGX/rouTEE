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
        case ERR_SGX_ERROR_SEAL_FAILED:
            return "sgx sealing failed";
        case ERR_SGX_ERROR_UNSEAL_FAILED:
            return "sgx unsealing failed";
        case ERR_SGX_ERROR_DECRYPT_FAILED:
            return "sgx decryption failed";
        default:
            return "wrong error index";
    }
}
