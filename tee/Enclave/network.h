#ifndef _NETWORK_H_
#define _NETWORK_H_

//
// opcodes for the command
//

// opcodes for test
#define OP_PUSH_A   97                  // a (cmd: a) (for ping test, round trip time test)

// opcodes for rouTEE host
#define OP_SET_ROUTING_FEE  104         // h (cmd: h fee)
#define OP_SET_ROUTING_FEE_ADDRESS  105 // i (cmd: i fee_addr)
#define OP_MAKE_SETTLE_TRANSACTION  110 // n (cmd: n)
#define OP_INSERT_BLOCK 111             // o (cmd: o block_number)
#define OP_INSERT_BLOCK_HEADER 100      // d (cmd: d block_number)
#define OP_SETTLE_ROUTING_FEE 118       // v (cmd: v amount)
#define OP_SYNC_WITH_BLOCKCHAIN 98      // b (cmd: b)
#define OP_PROCESS_ROUND 120            // x (cmd: x)

// opcodes for rouTEE users
#define OP_SECURE_COMMAND 112           // p (cmd: p sessionID encrypted_command_data)
#define OP_ADD_USER 118                 // v (cmd: v user_address settle_address public_key)
#define OP_GET_READY_FOR_DEPOSIT  106   // j (cmd: j beneficiary_address)
#define OP_UPDATE_LATEST_SPV_BLOCK 113  // q (cmd: q user_address block_number signature)
#define OP_DO_MULTIHOP_PAYMENT  109     // m (cmd: m sender_addr receiver_addr amount fee signature)
#define OP_SETTLE_BALANCE   108         // l (cmd: l receiver_addr amount fee signature)

// opcodes for rouTEE debugging
#define OP_PRINT_STATE  107             // k (cmd: k)
#define OP_INSERT_DEPOSIT_TX 114        // r (cmd: r sender_address amount block_number)
#define OP_INSERT_SETTLE_TX 117         // u (cmd: u)
#define OP_SEAL_STATE 119               // w (cmd: w)

#endif  // _NETWORK_H_