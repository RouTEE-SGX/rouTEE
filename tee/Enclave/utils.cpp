#include <stdio.h>
#include "utils.h"

string long_long_to_string(unsigned long long num) {
    char buffer[MAX_NUM_LENGTH];
    snprintf(buffer, MAX_NUM_LENGTH, "%llu", num);
    return string(buffer);
}

unsigned long long string_to_long_long(string str_num) {
    return strtoull(str_num.c_str(), NULL, 10);
}
