#ifndef _STATE_H_
#define _STATE_H_

#include "sgx_tcrypto.h"
#include "base58.h"

#include "routee.h"

#include <map>
#include <string>
#include <vector>
#include <queue>
using std::queue;
using std::priority_queue;
using std::vector;
using std::string;
using std::map;

// user account infos
class Account {

    public:
        // user balance amount
        unsigned long long balance;

        // prevent replay attack
        unsigned long long nonce;

        // max source block number
        unsigned long long min_requested_block_number;
        
        // boundary block number
        unsigned long long latest_SPV_block_number;

        // when user requests settlement, rouTEE sends balance to this address (34 bytes)
        char settle_address[BITCOIN_ADDRESS_LEN];
        
        // verify signature to authenticate (384 bytes)
        char public_key[RSA_PUBLIC_KEY_LEN];
};

// deposit sent by users to rouTEE
class Deposit {
    public:
        string tx_hash;
        int tx_index;
        string script;
        string manager_private_key;
};

class DepositRequest {
    public:
        // user should send deposit to this private key's address
        string manager_private_key;

        // when find deposit tx, balance goes to this address
        string beneficiary_address;

        // kind of timestamp: when the user requested deposit
        unsigned long long block_number;
};

// settle request
class SettleRequest {

    public:
        // user address who requested settlement
        string user_address;

        // address to receive on-chain asset
        string settle_address;

        // balance amount to settle
        unsigned long long amount;

        // fee for on-chain settlement transaction fee
        unsigned long long fee;
};

// infos for broadcasted on-chain settle tx, can be used to revert the settle tx later
class PendingSettleTxInfo {

    public:
        // tx hash of this pending settle tx
        string tx_hash;

        // sum of settle requests' amount
        unsigned long long pending_balances;

        // amount of pending routing fees to be confirmed for host
        unsigned long long to_be_confirmed_routing_fee;

        // on-chain tx fee for this settle tx
        unsigned long long on_chain_tx_fee;
        
        // settle requests for this pending settle tx
        queue<SettleRequest*> pending_settle_requests;

        // used deposits to make this pending settle tx
        queue<Deposit*> used_deposits;

        // left over deposit
        Deposit* leftover_deposit;
};

class TxFeeInfo {
    public:
        unsigned long long total_tx_fee;
        unsigned long long total_tx_size;

        TxFeeInfo(unsigned long long total_tx_fee, unsigned long long total_tx_size) {
            this->total_tx_fee = total_tx_fee;
            this->total_tx_size = total_tx_size;
        }

        ~TxFeeInfo() { }
};

class PaymentInfo {
    public:
        Account* receiver_account;
        unsigned long long amount;

        PaymentInfo(Account* receiver_account, unsigned long long amount) {
            this->receiver_account = receiver_account;
            this->amount = amount;
        }

        ~PaymentInfo() { }
};

// settle request compare for priority queue (increasing order)
struct srcompare {
    bool operator()(SettleRequest a, SettleRequest b){
        return a.fee > b.fee;
    }
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

        // minimum routing fee per multi-hop payment
        unsigned long long min_routing_fee;

        // address to get routing fees
        string fee_address;

        // block_hash[block_number] = block_hash
        map<unsigned long long, uint256> block_hash;

        // latest block number among blocks inside RouTEE
        unsigned long long latest_block_number;

        // about routing fee
        // (payment_count + deposit_count) * routing_fee = pending_routing_fee + routing_fee_pending + confirmed_routing_fee + d_settled_routing_fee
        unsigned long long pending_routing_fee;         // amount of fee which will be included in settle tx
        unsigned long long confirmed_routing_fee;       // amount of fee which is ready to be settled for rouTEE host
        
        // several infos for pending settle txs
        queue<PendingSettleTxInfo*> pending_settle_tx_infos;

        // users[user_address] = the user's Account
        map<string, Account*> users;

        // session keys with users
        // session_keys[session_ID] = session_key
        map<string, sgx_aes_gcm_128bit_key_t*> session_keys;

        // collected settle requests
        priority_queue<SettleRequest, vector<SettleRequest>, srcompare> settle_requests;

        // fee fund for on-chain settlement transaction fee
        // total amount of balances from users to pay on-chain settle tx fee, which rouTEE currently have (same as Reserve Requirement System)
        unsigned long long fee_fund;

        // sum of settle fees of all settlement requests
        unsigned long long collected_settle_fees;

        // average on-chain tx fee per byte
        // for simple test: set this 0, to make tx fee 0
        unsigned long long accumulated_tx_fee;
        unsigned long long accumulated_tx_size;
        unsigned long long avg_tx_fee_per_byte; // = accumulated_tx_fee / accumulated_tx_size;

        queue<TxFeeInfo> tx_fee_infos;

        // deposit_requests[keyID] = deposit_request (keyID: hash of pubkey in Bitcoin)
        map<string, DepositRequest*> deposit_requests;

        // confirmed unused deposits, which rouTEE currently owns
        queue<Deposit*> deposits;        

        // variables for debugging
        // d_total_deposit = total_balances + d_total_settle_amount + d_total_balances_for_settle_tx_fee
        //                  + pending_routing_fee + to_be_confirmed_routing_fee (calculated from pending settle tx info) + confirmed_routing_fee
        // d_total_balances_for_settle_tx_fee = balances_for_settle_tx_fee + d_total_settle_tx_fee
        unsigned long long d_total_deposit; // accumulated sum of all deposits
        unsigned long long d_total_balances_for_settle_tx_fee; // accumulated sum of taxes for settle tx fee
        unsigned long long d_total_settle_tx_fee; // accumulated sum of tx fee which rouTEE paid for all settle tx
        unsigned long long d_total_settle_amount; // accumulated sum of settle amount which users were paid actually
        unsigned long long d_settled_routing_fee; // amount of routing fee which is requested to be settled by rouTEE host (includes settle tx fee, not actually paid value)
};

#endif  // _STATE_H_