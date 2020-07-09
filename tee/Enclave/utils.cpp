#include <stdio.h>
#include "utils.h"

std::string long_long_to_string(unsigned long long num) {
    char buffer[20];
    snprintf(buffer, 20, "%llu", num);
    return std::string(buffer);
}

unsigned long long string_to_long_long(std::string str) {
    return (strtoull(str.c_str(), NULL, 10));
}
