#ifndef _STATE_H_
#define _STATE_H_

#include <map>
#include <string>
#include <vector>
using std::vector;
using std::string;
using std::map;

// user infos
class Account {

    public:
        unsigned long long balance;
        unsigned long long nonce;

        // if sender's min_requested_block_number <= receiver's latest_SPV_block_number, payment success
        unsigned long long min_requested_block_number;
        unsigned long long latest_SPV_block_number;
        
        // string public_key; // need this?
};

// settle request
class SettleRequest {

    public:
        string address;
        unsigned long long balance;
};

// global state
class State {

    public:
        // collect all fields as a string with delimitor
        string to_string();

        // restore state from string
        void from_string(string state_str);
        // vector<string> from_string(string state_str); // just for debugging, change return type as a void later

        // state version number (monotonically increasing counter)
        unsigned long long stateID;

        // key which is generated inside SGX (rouTEE's ID)
        string owner_address;
        string owner_public_key;
        string owner_private_key;

        // multi-hop payment fee
        unsigned long long routing_fee;

        // address to get routing fees
        string fee_address;

        // pending routing fees to owner
        // pending_fees[payment_paticipant's_address] = routing fees pending for him
        map<string, unsigned long long> pending_fees;

        // users[user_address] = the user's Account
        map<string, Account*> users;

        // settle requests
        vector<SettleRequest> settle_requests;

        // deposit transactions
        // string tx_ids;
        // unsigned int tx_indexes;
};

#endif  // _STATE_H_