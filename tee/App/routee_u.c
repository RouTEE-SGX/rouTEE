#include "routee_u.h"
#include <errno.h>

typedef struct ms_ecall_set_routing_fee_t {
	int ms_retval;
	unsigned long long ms_fee;
} ms_ecall_set_routing_fee_t;

typedef struct ms_ecall_set_routing_fee_address_t {
	int ms_retval;
	char* ms_fee_address;
	int ms_fee_addr_len;
} ms_ecall_set_routing_fee_address_t;

typedef struct ms_ecall_settle_routing_fee_t {
	int ms_retval;
	unsigned long long ms_amount;
} ms_ecall_settle_routing_fee_t;

typedef struct ms_ecall_make_settle_transaction_t {
	int ms_retval;
	char* ms_settle_transaction;
	int* ms_settle_tx_len;
} ms_ecall_make_settle_transaction_t;

typedef struct ms_ecall_secure_command_t {
	int ms_retval;
	char* ms_sessionID;
	int ms_sessionID_len;
	char* ms_encrypted_cmd;
	int ms_encrypted_cmd_len;
	char* ms_encrypted_response;
	int* ms_encrypted_response_len;
} ms_ecall_secure_command_t;

typedef struct ms_ecall_make_owner_key_t {
	int ms_retval;
	char* ms_sealed_owner_private_key;
	int* ms_sealed_key_len;
} ms_ecall_make_owner_key_t;

typedef struct ms_ecall_load_owner_key_t {
	int ms_retval;
	char* ms_sealed_owner_private_key;
	int ms_sealed_key_len;
} ms_ecall_load_owner_key_t;

typedef struct ms_ecall_seal_state_t {
	int ms_retval;
	char* ms_sealed_state;
	int* ms_sealed_state_len;
} ms_ecall_seal_state_t;

typedef struct ms_ecall_load_state_t {
	int ms_retval;
	char* ms_sealed_state;
	int ms_sealed_state_len;
} ms_ecall_load_state_t;

typedef struct ms_deal_with_deposit_tx_t {
	char* ms_sender_address;
	int ms_sender_addr_len;
	unsigned long long ms_amount;
	unsigned long long ms_block_number;
} ms_deal_with_deposit_tx_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL routee_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL routee_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL routee_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL routee_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL routee_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_routee = {
	5,
	{
		(void*)routee_ocall_print_string,
		(void*)routee_sgx_thread_wait_untrusted_event_ocall,
		(void*)routee_sgx_thread_set_untrusted_event_ocall,
		(void*)routee_sgx_thread_setwait_untrusted_events_ocall,
		(void*)routee_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_set_routing_fee(sgx_enclave_id_t eid, int* retval, unsigned long long fee)
{
	sgx_status_t status;
	ms_ecall_set_routing_fee_t ms;
	ms.ms_fee = fee;
	status = sgx_ecall(eid, 0, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_set_routing_fee_address(sgx_enclave_id_t eid, int* retval, const char* fee_address, int fee_addr_len)
{
	sgx_status_t status;
	ms_ecall_set_routing_fee_address_t ms;
	ms.ms_fee_address = (char*)fee_address;
	ms.ms_fee_addr_len = fee_addr_len;
	status = sgx_ecall(eid, 1, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_settle_routing_fee(sgx_enclave_id_t eid, int* retval, unsigned long long amount)
{
	sgx_status_t status;
	ms_ecall_settle_routing_fee_t ms;
	ms.ms_amount = amount;
	status = sgx_ecall(eid, 2, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_print_state(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_routee, NULL);
	return status;
}

sgx_status_t ecall_make_settle_transaction(sgx_enclave_id_t eid, int* retval, const char* settle_transaction, int* settle_tx_len)
{
	sgx_status_t status;
	ms_ecall_make_settle_transaction_t ms;
	ms.ms_settle_transaction = (char*)settle_transaction;
	ms.ms_settle_tx_len = settle_tx_len;
	status = sgx_ecall(eid, 4, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_secure_command(sgx_enclave_id_t eid, int* retval, const char* sessionID, int sessionID_len, const char* encrypted_cmd, int encrypted_cmd_len, char* encrypted_response, int* encrypted_response_len)
{
	sgx_status_t status;
	ms_ecall_secure_command_t ms;
	ms.ms_sessionID = (char*)sessionID;
	ms.ms_sessionID_len = sessionID_len;
	ms.ms_encrypted_cmd = (char*)encrypted_cmd;
	ms.ms_encrypted_cmd_len = encrypted_cmd_len;
	ms.ms_encrypted_response = encrypted_response;
	ms.ms_encrypted_response_len = encrypted_response_len;
	status = sgx_ecall(eid, 5, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_make_owner_key(sgx_enclave_id_t eid, int* retval, char* sealed_owner_private_key, int* sealed_key_len)
{
	sgx_status_t status;
	ms_ecall_make_owner_key_t ms;
	ms.ms_sealed_owner_private_key = sealed_owner_private_key;
	ms.ms_sealed_key_len = sealed_key_len;
	status = sgx_ecall(eid, 6, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_load_owner_key(sgx_enclave_id_t eid, int* retval, const char* sealed_owner_private_key, int sealed_key_len)
{
	sgx_status_t status;
	ms_ecall_load_owner_key_t ms;
	ms.ms_sealed_owner_private_key = (char*)sealed_owner_private_key;
	ms.ms_sealed_key_len = sealed_key_len;
	status = sgx_ecall(eid, 7, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_seal_state(sgx_enclave_id_t eid, int* retval, char* sealed_state, int* sealed_state_len)
{
	sgx_status_t status;
	ms_ecall_seal_state_t ms;
	ms.ms_sealed_state = sealed_state;
	ms.ms_sealed_state_len = sealed_state_len;
	status = sgx_ecall(eid, 8, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_load_state(sgx_enclave_id_t eid, int* retval, const char* sealed_state, int sealed_state_len)
{
	sgx_status_t status;
	ms_ecall_load_state_t ms;
	ms.ms_sealed_state = (char*)sealed_state;
	ms.ms_sealed_state_len = sealed_state_len;
	status = sgx_ecall(eid, 9, &ocall_table_routee, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t deal_with_deposit_tx(sgx_enclave_id_t eid, const char* sender_address, int sender_addr_len, unsigned long long amount, unsigned long long block_number)
{
	sgx_status_t status;
	ms_deal_with_deposit_tx_t ms;
	ms.ms_sender_address = (char*)sender_address;
	ms.ms_sender_addr_len = sender_addr_len;
	ms.ms_amount = amount;
	ms.ms_block_number = block_number;
	status = sgx_ecall(eid, 10, &ocall_table_routee, &ms);
	return status;
}

sgx_status_t deal_with_settlement_tx(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 11, &ocall_table_routee, NULL);
	return status;
}

