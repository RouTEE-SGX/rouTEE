#ifndef _NETWORK_H_
#define _NETWORK_H_

// opcodes for the command
#define OP_PUSH_A   97 // a

#define OP_SET_ROUTING_FEE  104 // h (cmd: h fee)
#define OP_SET_ROUTING_FEE_ADDRESS  105 // i (cmd: i fee_addr)
#define OP_GET_READY_FOR_DEPOSIT  106 // j (cmd: j sender_address settle_address)
#define OP_PRINT_STATE  107 // k (cmd: k)
#define OP_SETTLE_BALANCE   108 // l (cmd: l receiver_addr amount)
#define OP_DO_MULTIHOP_PAYMENT  109 // m (cmd: m sender_addr receiver_addr amount fee)
#define OP_MAKE_SETTLE_TRANSACTION  110 // n (cmd: n)
#define OP_INSERT_BLOCK 111 // o (cmd: o block_data)
#define OP_SECURE_COMMAND 112 // p (cmd: p sessionID encrypted_command_data)
#define OP_UPDATE_LATEST_SPV_BLOCK 113 // q (cmd: q user_address blocknumber)
#define OP_INSERT_DEPOSIT_TX 114 // r (cmd: r sender_address amount block_number)
#define OP_INSERT_SETTLE_TX 117 // u (cmd: u)
#define OP_SETTLE_ROUTING_FEE 118 // v (cmd: v amount)

#endif  // _NETWORK_H_