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
            return "the user has not enough balance to pay that amount";
        default:
            return "wrong error index";
    }
}
