#ifndef ROUTEE_U_H__
#define ROUTEE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_set_routing_fee(sgx_enclave_id_t eid, int* retval, unsigned long long fee);
sgx_status_t ecall_set_routing_fee_address(sgx_enclave_id_t eid, int* retval, const char* fee_address, int fee_addr_len);
sgx_status_t ecall_settle_routing_fee(sgx_enclave_id_t eid, int* retval, unsigned long long amount);
sgx_status_t ecall_print_state(sgx_enclave_id_t eid);
sgx_status_t ecall_make_settle_transaction(sgx_enclave_id_t eid, int* retval, const char* settle_transaction, int* settle_tx_len);
sgx_status_t ecall_secure_command(sgx_enclave_id_t eid, int* retval, const char* sessionID, int sessionID_len, const char* encrypted_cmd, int encrypted_cmd_len, char* encrypted_response, int* encrypted_response_len);
sgx_status_t ecall_make_owner_key(sgx_enclave_id_t eid, int* retval, char* sealed_owner_private_key, int* sealed_key_len);
sgx_status_t ecall_load_owner_key(sgx_enclave_id_t eid, int* retval, const char* sealed_owner_private_key, int sealed_key_len);
sgx_status_t ecall_seal_state(sgx_enclave_id_t eid, int* retval, char* sealed_state, int* sealed_state_len);
sgx_status_t ecall_load_state(sgx_enclave_id_t eid, int* retval, const char* sealed_state, int sealed_state_len);
sgx_status_t deal_with_deposit_tx(sgx_enclave_id_t eid, const char* sender_address, int sender_addr_len, unsigned long long amount, unsigned long long block_number);
sgx_status_t deal_with_settlement_tx(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
