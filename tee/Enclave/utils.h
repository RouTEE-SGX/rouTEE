#ifndef _UTILS_H_
#define _UTILS_H_

#include <string>
using std::string;

#define MAX_NUM_LENGTH 30

string long_long_to_string(unsigned long long num);
unsigned long long string_to_long_long(string str);

#endif  // _UTILS_H_