#include "state.h"
#include "utils.h"

// collect all state fields as a string with delimitor
string State::to_string() {

    string delimitor = ",";

    // stateID
    string state_str = long_long_to_string(this->stateID) + delimitor;

    // owner
    state_str += this->owner_address + delimitor;
    state_str += this->owner_public_key + delimitor;
    state_str += this->owner_private_key + delimitor;

    // fee
    state_str += long_long_to_string(this->routing_fee) + delimitor;
    state_str += this->fee_address + delimitor;
    state_str += long_long_to_string(this->pending_fees.size()) + delimitor;
    for (map<string, unsigned long long>::iterator iter = this->pending_fees.begin(); iter != this->pending_fees.end(); iter++){
        state_str += iter->first + delimitor + long_long_to_string(iter->second) + delimitor;
    }

    // users
    state_str += long_long_to_string(this->users.size()) + delimitor;
    for (map<string, Account*>::iterator iter = this->users.begin(); iter != this->users.end(); iter++){
        state_str += iter->first + delimitor + long_long_to_string(iter->second->balance) + delimitor + long_long_to_string(iter->second->nonce) + delimitor;
    }

    return state_str;
}

// restore state from string
vector<string> State::from_string(string state_str) {
    // split string with delimitor
    string delimiter = ",";
    size_t pos = 0;
    string token;
    vector<string> fields;
    while ((pos = state_str.find(delimiter)) != std::string::npos) {
        token = state_str.substr(0, pos);
        fields.push_back(token);
        state_str.erase(0, pos + delimiter.length());
    }

    // restore state

    // stateID
    int cnt = 0;
    this->stateID = string_to_long_long(fields[cnt++]);

    // owner
    this->owner_address = fields[cnt++];
    this->owner_public_key = fields[cnt++];
    this->owner_private_key = fields[cnt++];

    // fee
    this->routing_fee = string_to_long_long(fields[cnt++]);
    this->fee_address = fields[cnt++];
    this->pending_fees.clear();
    int map_size = string_to_long_long(fields[cnt++]);
    for (int i = 0; i < map_size; i++) {
        this->pending_fees[fields[cnt++]] = string_to_long_long(fields[cnt++]);
    }

    // users
    this->users.clear();
    map_size = string_to_long_long(fields[cnt++]);
    for (int i = 0; i < map_size; i++) {
        Account* acc = new Account;
        string user_addr = fields[cnt++];
        acc->balance = string_to_long_long(fields[cnt++]);
        acc->nonce = string_to_long_long(fields[cnt++]);
        this->users[user_addr] = acc;
    }
    
    return fields;
}
