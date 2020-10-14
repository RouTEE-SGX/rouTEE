#ifndef _STATE_H_
#define _STATE_H_

#include <string>
#include <map>
#include <set>
#include <vector>

#include "service_provider.h"

// TODO: update enclave state checks for ghost, primary, backups and also multiple channels
// enclave state machine
// protects enclave (can only ascend through enclaveState, 1 state at a time)
// must choose between primary or backup
// if primary, must choose between initiator, or non initiator when ascending
enum TeechanState {
	Ghost, // ghost enclave created

	Backup, // enclave is backup -- never changes state from this

	Primary, // enclave is assigned primary
	WaitingForFunds, // enclave is waiting for funding
	Funded, // enclave has been funded
    Ready, // enclave routing fee and routing fee address configuration has been finished
};

// Represents a deposit (or unspent output) in the Setup Transaction
class Deposit {
    public:
        bool is_spent;

        std::string bitcoin_address;
        std::string public_key;
        std::string private_key;

        std::string script;

        std::string txid;
        unsigned long long tx_index;
        unsigned long long deposit_amount;

};

// Setup transaction state for the on-chain setup transaction.
// Vectors that store the deposit amounts, bitcoin addresses, public
// and private keys are all ordered (e.g. to find the private key
// of a public key at vector index i, you just look up the same index
// in the private key vector)
// The deposit IDs are the index where they are stored in the vector.
class SetupTransaction {
    public:
        // Input transaction information and keys to construct the setup transaction
        std::string public_key;
        std::string private_key;
        std::string utxo_hash;
        unsigned long long utxo_index;
        std::string utxo_script;

        // Setup transaction to place onto the blockchain
        std::string setup_transaction_hash;

        // Assignments from deposit indexes to deposits
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits;

        // Assignments from deposit indexes to channel IDs
        std::map<unsigned long long, std::string> deposit_ids_to_channels;

        // Bitcoin address to pay when a channel is closed
        std::string my_address;

        // Bitcoin miner fee to pay whenver I generate a transaction
        unsigned long long miner_fee;
};

extern TeechanState teechain_state;
bool check_state(TeechanState state);

// user infos
class Account {

    public:
        unsigned long long balance;         // Balance for this account
        unsigned long long nonce;           // To prevent replay attack
        unsigned long long pending_fee;    // Pending routing fee for this account
        bool settle_request;        // True if there was a settle request
        unsigned long long settle_amount;
        // std::string public_key; // need this?
        //TeechanState state;
};

// settle request
class SettleRequest {

    public:
        std::string address;
        unsigned long long balance;
};

// global state
class State {

    public:
        // collect all fields as a string with delimitor
        std::string to_string();
        // restore state from string
        void from_string(std::string state_str);
        // std::vector<std::string> from_string(std::string state_str); // just for debugging, change return type as a void later

        // state version number (monotonically increasing counter)
        unsigned long long stateID;

        // key which is generated in SGX (owner account of rouTEE)
        unsigned long long owner_certificate;
        std::string owner_address;
        std::string owner_public_key;
        std::string owner_private_key;
        std::string owner_script;

        // multi-hop payment fee
        unsigned long long routing_fee;
        // address to get routing fees
        std::string fee_address;
        // pending routing fees to owner
        // pending_fees[payment_paticipant's_address] = routing fees pending for him
        //std::map<std::string, unsigned long long> pending_fees;

        // users[user_address] = the user's Account
        std::map<std::string, Account*> users;

        std::vector<std::string> wait_funding_list;
        // settle requests
        //std::vector<SettleRequest> settle_requests;
        //std::map<std::string, unsigned long long> settle_requests;

        // deposit transactions
        // std::string tx_ids;
        // unsigned int tx_indexes;
};

#endif
