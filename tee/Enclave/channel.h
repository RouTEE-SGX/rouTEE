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
};

// global channels array
// Channel* channels = new Channel[10];

// user address to the user's channels
map< string, vector<Channel *> > addresses_to_channels;

#endif  // _CHANNEL_H_