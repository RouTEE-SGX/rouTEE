#ifndef _NETWORK_H_
#define _NETWORK_H_

// opcodes for the command
#define OP_HELLO_WORLD  97 // = a
#define OP_PUSH_A   98 // b
#define OP_ADD_CHANNEL   99 // c
#define OP_PRINT_CHANNELS   100 // d
#define OP_REMOVE_CHANNEL   101 // e
#define OP_DO_PAYMENT   102 // f
#define OP_GET_CHANNEL_BALANCE  103 // g

#define OP_SET_ROUTING_FEE  104 // h (cmd: h fee)
#define OP_SET_ROUTING_FEE_ADDRESS  105 // i (cmd: i fee_addr)
#define OP_CREATE_CHANNEL  106 // j (cmd: j tx_id tx_index)
#define OP_PRINT_STATE  107 // k (cmd: k)
#define OP_SETTLE_BALANCE   108 // l (cmd: l receiver_addr)
#define OP_DO_MULTIHOP_PAYMENT  109 // m (cmd: m sender_addr receiver_addr amount fee)
#define OP_MAKE_SETTLE_TRANSACTION  110 // n (cmd: n)
#define OP_INSERT_BLOCK 111 // o (cmd: o block_data)
#define OP_SECURE_COMMAND 112 // p (cmd: p sessionID encrypted_command_data)

#endif  // _NETWORK_H_