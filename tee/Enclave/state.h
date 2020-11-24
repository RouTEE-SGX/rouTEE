#ifndef _STATE_H_
#define _STATE_H_

#include "sgx_tcrypto.h"

#include "base58.h"

#include <map>
#include <string>
#include <vector>
#include <queue>
using std::queue;
using std::vector;
using std::string;
using std::map;

class TxOut {
    public:
        unsigned long long amount;
        std::string txid;
        int tx_index;
};

// user account infos
class Account {

    public:
        unsigned long long balance;
        unsigned long long nonce;

        // if sender's min_requested_block_number <= receiver's latest_SPV_block_number, payment success
        unsigned long long min_requested_block_number;
        unsigned long long latest_SPV_block_number;

        // when user requests settlement, rouTEE sends balance to this address
        string settle_address;
        
        string public_key; // need this?
};

// deposit sent by users to rouTEE
class Deposit {
    public:
        string tx_hash;
        int tx_index;
        string manager_private_key;
};

class DepositRequest {
    public:
        // user should send deposit to this private key's address
        string manager_private_key;

        // when find deposit tx, balance goes to this address
        string sender_address;

        // when the user requests settlement, balances goes to this address
        string settle_address;

        // kind of timestamp: when the user requested deposit
        unsigned long long block_number;

        string public_key;
};

// settle request
class SettleRequest {

    public:
        // address of user who requested settlement
        string address;

        // settle request amount
        unsigned long long amount;

        // tax for settlement to pay settle tx fee
        // so user actually get settled (amount - balance_for_settle_tx_fee)
        // this is calculated at ecall_make_settle_transaction()
        unsigned long long balance_for_settle_tx_fee;
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
        queue<SettleRequest*> pending_settle_requests;

        // used deposits to make this pending settle tx
        queue<Deposit*> used_deposits;

        // left over deposit
        Deposit* leftover_deposit;
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

        // public key for checking rouTEE host's authority
        string host_public_key;

        // total amount of user balances in rouTEE
        unsigned long long total_balances;

        // multi-hop payment routing fee per payment
        unsigned long long routing_fee;

        // address to get routing fees
        string fee_address;

        map<unsigned long long, uint256> block_hash;
        unsigned long long block_number;

        // about routing fee
        // (payment_count + deposit_count) * routing_fee = routing_fee_waiting + routing_fee_pending + routing_fee_confirmed + routing_fee_settled
        unsigned long long routing_fee_waiting;         // amount of fee which will be included in settle tx
        unsigned long long routing_fee_confirmed;       // amount of fee which is ready to be settled for rouTEE host
        unsigned long long routing_fee_settled;         // amount of fee which is requested to be settled by rouTEE host (includes settle tx fee, not actually paid value)

        // several infos for pending settle txs
        queue<PendingSettleTxInfo*> pending_settle_tx_infos;

        // users[user_address] = the user's Account
        map<string, Account*> users;

        // session keys with users
        // session_keys[session_ID] = session_key
        map<string, sgx_aes_gcm_128bit_key_t*> session_keys;

        map<string, string> verify_keys;

        // waiting settle requests
        queue<SettleRequest*> settle_requests_waiting;

        // total amount of balances from users to pay on-chain settle tx fee, which rouTEE currently have (same as Reserve Requirement System)
        unsigned long long balances_for_settle_tx_fee;

        // average on-chain tx fee per byte
        // for simple test: set this 0, to make tx fee 0
        unsigned long long avg_tx_fee_per_byte = 100;

        // deposit_requests[manager_address] = deposit_request
        map<string, DepositRequest*> deposit_requests;

        // confirmed unused deposits, which rouTEE currently owns
        queue<Deposit*> deposits;        

        // bitcoin block headers
        // vector<Block> blocks;

        // variables for debugging
        // d_total_deposit = total_balances + d_total_settle_amount + d_total_balances_for_settle_tx_fee
        //                  + routing_fee_waiting + pending_routing_fees (calculated from pending settle tx info) + routing_fee_confirmed
        // d_total_balances_for_settle_tx_fee = balances_for_settle_tx_fee + d_total_settle_tx_fee
        unsigned long long d_total_deposit; // accumulated sum of all deposits
        unsigned long long d_total_balances_for_settle_tx_fee; // accumulated sum of taxes for settle tx fee
        unsigned long long d_total_settle_tx_fee; // accumulated sum of tx fee which rouTEE paid for all settle tx
        unsigned long long d_total_settle_amount; // accumulated sum of settle amount which users were paid actually

};

#endif  // _STATE_H_