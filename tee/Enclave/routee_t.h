#ifndef ROUTEE_T_H__
#define ROUTEE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_set_routing_fee(unsigned long long fee);
int ecall_set_routing_fee_address(const char* fee_address, int fee_addr_len);
int ecall_settle_routing_fee(unsigned long long amount);
void ecall_print_state();
int ecall_make_settle_transaction(const char* settle_transaction, int* settle_tx_len);
int ecall_secure_command(const char* sessionID, int sessionID_len, const char* encrypted_cmd, int encrypted_cmd_len, char* encrypted_response, int* encrypted_response_len);
int ecall_make_owner_key(char* sealed_owner_private_key, int* sealed_key_len);
int ecall_load_owner_key(const char* sealed_owner_private_key, int sealed_key_len);
int ecall_seal_state(char* sealed_state, int* sealed_state_len);
int ecall_load_state(const char* sealed_state, int sealed_state_len);
void deal_with_deposit_tx(const char* sender_address, int sender_addr_len, unsigned long long amount, unsigned long long block_number);
void deal_with_settlement_tx();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
