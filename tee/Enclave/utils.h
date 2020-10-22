#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>

#include <string>
#include <vector>
using std::vector;
using std::string;

#define MAX_NUM_LENGTH 30

string long_long_to_string(unsigned long long num);
unsigned long long string_to_long_long(string str);
void pseudo_sleep(long long int sec);
void split(const string &cmd, vector<string> &params, char delimiter);

#endif  // _UTILS_H_