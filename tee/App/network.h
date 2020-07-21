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
#define OP_SET_ROUTING_FEE  104 // h
#define OP_SET_ROUTING_FEE_ADDRESS  105 // i
#define OP_CREATE_CHANNEL  106 // j
#define OP_PRINT_STATE  107 // k
#define OP_SETTLE_BALANCE   108 // l
#define OP_DO_MULTIHOP_PAYMENT  109 // m

#endif  // _NETWORK_H_