#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <map>
#include <vector>
#include <string>
using std::string;
using std::vector;
using std::map;

class Channel {

    public:
        // users key info
        string addresses[2];
        string public_keys[2];
        string private_keys[2];

        unsigned long long balances[2];

        // tx info
        string tx_id;
        int tx_index;

        // rouTEE params
        unsigned long long route_fee;

        // get channel info as a string
        string to_string();
};

#endif  // _CHANNEL_H_