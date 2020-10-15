#ifndef _PQV_H_
#define _PQV_H_

#include <map>
#include <string>
#include <vector>
using std::vector;
using std::string;
using std::map;

// voting transaction
class Transaction {

    public:

        // policy index
        unsigned int policy_index;

        // # of voting ballot for the policy
        unsigned int ballot_num;
};

// election class
class Election {

    public:

        // election ID
        string electionID;

        // # of policies
        unsigned int policy_num;

        // ballot_box[policy_index] = ballot count
        unsigned int* ballot_box;

        // voting transactions
        vector<Transaction*> transactions;

        // # of total ballot
        unsigned int total_ballot_num;
};

// class Elections {
//     public:
//         map<string, Election*> elections;
// };

#endif  // _PQV_H_