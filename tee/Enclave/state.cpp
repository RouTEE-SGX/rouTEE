#include "state.h"
#include "utils.h"

// collect all state fields as a string with delimitor
string State::to_string() {

    string state_str = "";
    string delimitor = ",";

    // stateID
    state_str += long_long_to_string(this->stateID) + delimitor;

    // // fee
    // state_str += long_long_to_string(this->routing_fee) + delimitor;
    // state_str += this->fee_address + delimitor;
    // state_str += long_long_to_string(this->pending_fees.size()) + delimitor;
    // for (map<string, unsigned long long>::iterator iter = this->pending_fees.begin(); iter != this->pending_fees.end(); iter++){
    //     state_str += iter->first + delimitor + long_long_to_string(iter->second) + delimitor;
    // }

    // // users
    // state_str += long_long_to_string(this->users.size()) + delimitor;
    // for (map<string, Account*>::iterator iter = this->users.begin(); iter != this->users.end(); iter++){
    //     state_str += iter->first + delimitor + long_long_to_string(iter->second->balance) + delimitor + long_long_to_string(iter->second->nonce) + delimitor;
    // }

    return state_str;
}

// cut out a string token from long string
string get_token(string& state_str) {
    // split string with delimitor
    string delimiter = ",";
    size_t pos = 0;
    string token = "";
    if ((pos = state_str.find(delimiter)) != std::string::npos) {
        token = state_str.substr(0, pos);
        state_str.erase(0, pos + delimiter.length());
        return token;
    }
    return token;
}

// restore state from string
void State::from_string(string state_str) {
    // // restore state

    // // stateID
    // int cnt = 0;
    // this->stateID = string_to_long_long(get_token(state_str));

    // // fee
    // this->routing_fee = string_to_long_long(get_token(state_str));
    // this->fee_address = get_token(state_str);
    // this->pending_fees.clear();
    // int map_size = string_to_long_long(get_token(state_str));
    // for (int i = 0; i < map_size; i++) {
    //     this->pending_fees[get_token(state_str)] = string_to_long_long(get_token(state_str));
    // }

    // // users
    // this->users.clear();
    // map_size = string_to_long_long(get_token(state_str));
    // for (int i = 0; i < map_size; i++) {
    //     Account* acc = new Account;
    //     string user_addr = get_token(state_str);
    //     acc->balance = string_to_long_long(get_token(state_str));
    //     acc->nonce = string_to_long_long(get_token(state_str));
    //     this->users[user_addr] = acc;
    // }
    
}
