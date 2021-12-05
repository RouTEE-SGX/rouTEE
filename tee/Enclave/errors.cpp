#include "errors.h"

string error_to_msg(int err) {
    switch(err) {
        case NO_ERROR:
            return "SUCCESS";
        case ERR_INVALID_OP_CODE:
            return "ERROR: this op code doesn't exist";
        case ERR_INVALID_PARAMS:
            return "ERROR: invalid op params";
        case ERR_NOT_ENOUGH_BALANCE:
            return "ERROR: the user has not enough balance";
        case ERR_NOT_ENOUGH_FEE:
            return "ERROR: need higher routing fee";
        case ERR_SGX_ERROR_UNEXPECTED:
            return "ERROR: sgx error: SGX_ERROR_UNEXPECTED";
        case ERR_SEAL_FAILED:
            return "ERROR: sealing failed";
        case ERR_UNSEAL_FAILED:
            return "ERROR: unsealing failed";
        case ERR_DECRYPT_FAILED:
            return "ERROR: AES-GCM decryption failed";
        case ERR_ENCRYPT_FAILED:
            return "ERROR: AES-GCM encryption failed";
        case ERR_NO_RECEIVER:
            return "ERROR: payment receiver not exists in state";
        case ERR_RECEIVER_NOT_READY:
            return "ERROR: payment receiver has old boundary block number";
        case ERR_SETTLE_NOT_READY:
            return "ERROR: not ready for settlement yet";
        case ERR_CANNOT_CHANGE_TO_LOWER_BLOCK:
            return "ERROR: cannot change to lower block";
        case ERR_TOO_LOW_AMOUNT_TO_SETTLE:
            return "ERROR: too low amount to settle";
        case ERR_TOO_LOW_DEPOSIT:
            return "ERROR: too low amount of deposit";
        case ERR_NO_AUTHORITY:
            return "ERROR: this user doesn't have authority";
        case ERR_NO_USER_ACCOUNT:
            return "ERROR: no user account exists for this address";
        case ERR_VERIFY_SIG_FAILED:
            return "ERROR: signature verification failed";
        default:
            return "ERROR: this error index does not exist";
    }
}
