#ifndef _STATE_H_
#define _STATE_H_

#include <map>
#include <string>
using std::string;
using std::map;

class State {

    public:
        // key which is generated in SGX (owner account of rouTEE)
        string owner_address;
        string owner_public_key;
        string owner_private_key;

        // multi-hop payment fee
        unsigned long long routing_fee;
        // address to get routing fees
        string fee_address;

        // map[user_address] = user_balance
        map<string, unsigned long long> user_balances;

        // deposit transactions
        // string tx_ids;
        // unsigned int tx_indexes;
};

#endif  // _STATE_H_