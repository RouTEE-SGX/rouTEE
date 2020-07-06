#include "errors.h"

const char* error_to_msg(int err) {
    switch(err) {
        case NO_ERROR:
            return "SUCCESS";
        case ERR_INVALID_OP_CODE:
            return "this op code doesn't exist";
        case ERR_INVALID_CHANNEL:
            return "invalid channel";
        default:
            return "wrong error index";
    }
}
