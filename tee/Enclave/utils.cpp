#include "utils.h"

string long_long_to_string(unsigned long long num) {
    char buffer[MAX_NUM_LENGTH];
    snprintf(buffer, MAX_NUM_LENGTH, "%llu", num);
    return string(buffer);
}

unsigned long long string_to_long_long(string str_num) {
    return strtoull(str_num.c_str(), NULL, 10);
}

void pseudo_sleep(long long int sec) {
    for (long long int i = 0; i < sec * 1000000000; i++) {
        // just time consuming work
        // almost same as --> sleep(sec);
    }
}

void split(const string &cmd, vector<string> &params, char delimiter) {
    size_t pos = cmd.find(delimiter);
    size_t initialPos = 0;
    params.clear();

    // Decompose statement
    while(pos != string::npos) {
        params.push_back(cmd.substr(initialPos, pos - initialPos));
        initialPos = pos + 1;

        pos = cmd.find(delimiter, initialPos);
    }

    // Add the last one
    params.push_back(cmd.substr(initialPos, std::min(pos, cmd.size()) - initialPos + 1));
}
