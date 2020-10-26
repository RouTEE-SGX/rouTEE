#ifndef _STATE_H_
#define _STATE_H_

#include "sgx_tcrypto.h"

#include <map>
#include <string>
#include <vector>
#include <queue>
using std::queue;
using std::vector;
using std::string;
using std::map;

// user account infos
class Account {

    public:
        unsigned long long balance;
        unsigned long long nonce;

        // if sender's min_requested_block_number <= receiver's latest_SPV_block_number, payment success
        unsigned long long min_requested_block_number;
        unsigned long long latest_SPV_block_number;
        
        // string public_key; // need this?
};

// deposit sent by users to rouTEE
class Deposit {
    public:
        string tx_hash;
        int tx_index;
        string manager_private_key;
};

// settle request
class SettleRequest {

    public:
        string address;
        unsigned long long amount;
};

// infos for broadcasted settle tx, can be used to revert the settle tx later
class PendingSettleTxInfo {

    public:
        // tx hash of this pending settle tx
        string tx_hash;

        // sum of settle requests' amount
        unsigned long long pending_balances;

        // sum of routing fees which will be paid to fee address
        unsigned long long pending_routing_fees;

        // tx fee for this pending settle tx
        unsigned long long pending_tx_fee;
        
        // settle requests for this pending settle tx
        queue<SettleRequest> pending_settle_requests;

        // used deposits to make this pending settle tx
        queue<Deposit> used_deposits;

        // left over deposit
        Deposit leftover_deposit;
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

        // randomly generated keys to receive deposit from users
        // manager_private_keys[manager_address] = manager_private_key
        map<string, string> manager_private_keys;

        // total amount of user balances in rouTEE
        unsigned long long total_balances;

        // multi-hop payment routing fee per payment
        unsigned long long routing_fee;

        // address to get routing fees
        string fee_address;

        // about routing fee
        unsigned long long routing_fee_waiting;         // amount of fee which will be included in settle tx
        unsigned long long routing_fee_confirmed;       // amount of fee which is ready to be settled for rouTEE host
        
        // several infos for pending settle txs
        queue<PendingSettleTxInfo> pending_settle_tx_infos;

        // users[user_address] = the user's Account
        map<string, Account*> users;

        // session keys with users
        // session_keys[session_ID] = session_key
        map<string, sgx_aes_gcm_128bit_key_t*> session_keys;

        // minimum number of users to make settlement tx
        // ex. 1 means make settlement tx for every settlement request
        int min_settle_users_num = 1;

        // waiting settle requests
        queue<SettleRequest> settle_requests_waiting;

        // total amount of balances from users to pay on-chain settle tx fee
        unsigned long long balances_for_settle_tx_fee;

        // average on-chain tx fee per byte
        // for simple test: set this 0, to make tx fee 0
        unsigned long long avg_tx_fee_per_byte;

        // deposits
        queue<Deposit> deposits;
        // string tx_ids;
        // unsigned int tx_indexes;

        // bitcoin block headers
        // queue<Block> blocks;

};

#endif  // _STATE_H_