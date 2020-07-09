#include "channel.h"
#include "utils.h"

#include <stdio.h>

string Channel::to_string() {
    string ch_str = this->addresses[0] + ":" + long_long_to_string(this->balances[0]) + " / " + this->addresses[1] + ":" + long_long_to_string(this->balances[1]);
    return ch_str;
}
