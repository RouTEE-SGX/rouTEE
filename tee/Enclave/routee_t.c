#include "routee_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_ecall_set_routing_fee(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_set_routing_fee_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_set_routing_fee_t* ms = SGX_CAST(ms_ecall_set_routing_fee_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_set_routing_fee(ms->ms_fee);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_set_routing_fee_address(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_set_routing_fee_address_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_set_routing_fee_address_t* ms = SGX_CAST(ms_ecall_set_routing_fee_address_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_fee_address = ms->ms_fee_address;
	int _tmp_fee_addr_len = ms->ms_fee_addr_len;
	size_t _len_fee_address = _tmp_fee_addr_len;
	char* _in_fee_address = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fee_address, _len_fee_address);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fee_address != NULL && _len_fee_address != 0) {
		_in_fee_address = (char*)malloc(_len_fee_address);
		if (_in_fee_address == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_fee_address, _tmp_fee_address, _len_fee_address);
	}

	ms->ms_retval = ecall_set_routing_fee_address((const char*)_in_fee_address, _tmp_fee_addr_len);
err:
	if (_in_fee_address) free((void*)_in_fee_address);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_settle_routing_fee(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_settle_routing_fee_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_settle_routing_fee_t* ms = SGX_CAST(ms_ecall_settle_routing_fee_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_settle_routing_fee(ms->ms_amount);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_print_state(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_print_state();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_make_settle_transaction(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_make_settle_transaction_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_make_settle_transaction_t* ms = SGX_CAST(ms_ecall_make_settle_transaction_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_settle_transaction = ms->ms_settle_transaction;
	int* _tmp_settle_tx_len = ms->ms_settle_tx_len;
	size_t _len_settle_tx_len = sizeof(int);
	int* _in_settle_tx_len = NULL;

	CHECK_UNIQUE_POINTER(_tmp_settle_tx_len, _len_settle_tx_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_settle_tx_len != NULL && _len_settle_tx_len != 0) {
		_in_settle_tx_len = (int*)malloc(_len_settle_tx_len);
		if (_in_settle_tx_len == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_settle_tx_len, _tmp_settle_tx_len, _len_settle_tx_len);
	}

	ms->ms_retval = ecall_make_settle_transaction((const char*)_tmp_settle_transaction, _in_settle_tx_len);
err:
	if (_in_settle_tx_len) {
		memcpy(_tmp_settle_tx_len, _in_settle_tx_len, _len_settle_tx_len);
		free(_in_settle_tx_len);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_secure_command(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_secure_command_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_secure_command_t* ms = SGX_CAST(ms_ecall_secure_command_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sessionID = ms->ms_sessionID;
	int _tmp_sessionID_len = ms->ms_sessionID_len;
	size_t _len_sessionID = _tmp_sessionID_len;
	char* _in_sessionID = NULL;
	char* _tmp_encrypted_cmd = ms->ms_encrypted_cmd;
	int _tmp_encrypted_cmd_len = ms->ms_encrypted_cmd_len;
	size_t _len_encrypted_cmd = _tmp_encrypted_cmd_len;
	char* _in_encrypted_cmd = NULL;
	char* _tmp_encrypted_response = ms->ms_encrypted_response;
	int* _tmp_encrypted_response_len = ms->ms_encrypted_response_len;
	size_t _len_encrypted_response_len = sizeof(int);
	int* _in_encrypted_response_len = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sessionID, _len_sessionID);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_cmd, _len_encrypted_cmd);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_response_len, _len_encrypted_response_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sessionID != NULL && _len_sessionID != 0) {
		_in_sessionID = (char*)malloc(_len_sessionID);
		if (_in_sessionID == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_sessionID, _tmp_sessionID, _len_sessionID);
	}
	if (_tmp_encrypted_cmd != NULL && _len_encrypted_cmd != 0) {
		_in_encrypted_cmd = (char*)malloc(_len_encrypted_cmd);
		if (_in_encrypted_cmd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_encrypted_cmd, _tmp_encrypted_cmd, _len_encrypted_cmd);
	}
	if (_tmp_encrypted_response_len != NULL && _len_encrypted_response_len != 0) {
		_in_encrypted_response_len = (int*)malloc(_len_encrypted_response_len);
		if (_in_encrypted_response_len == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_encrypted_response_len, _tmp_encrypted_response_len, _len_encrypted_response_len);
	}

	ms->ms_retval = ecall_secure_command((const char*)_in_sessionID, _tmp_sessionID_len, (const char*)_in_encrypted_cmd, _tmp_encrypted_cmd_len, _tmp_encrypted_response, _in_encrypted_response_len);
err:
	if (_in_sessionID) free((void*)_in_sessionID);
	if (_in_encrypted_cmd) free((void*)_in_encrypted_cmd);
	if (_in_encrypted_response_len) {
		memcpy(_tmp_encrypted_response_len, _in_encrypted_response_len, _len_encrypted_response_len);
		free(_in_encrypted_response_len);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_make_owner_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_make_owner_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_make_owner_key_t* ms = SGX_CAST(ms_ecall_make_owner_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sealed_owner_private_key = ms->ms_sealed_owner_private_key;
	int* _tmp_sealed_key_len = ms->ms_sealed_key_len;
	size_t _len_sealed_key_len = sizeof(int);
	int* _in_sealed_key_len = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_key_len, _len_sealed_key_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_key_len != NULL && _len_sealed_key_len != 0) {
		_in_sealed_key_len = (int*)malloc(_len_sealed_key_len);
		if (_in_sealed_key_len == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_key_len, _tmp_sealed_key_len, _len_sealed_key_len);
	}

	ms->ms_retval = ecall_make_owner_key(_tmp_sealed_owner_private_key, _in_sealed_key_len);
err:
	if (_in_sealed_key_len) {
		memcpy(_tmp_sealed_key_len, _in_sealed_key_len, _len_sealed_key_len);
		free(_in_sealed_key_len);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_owner_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_owner_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_owner_key_t* ms = SGX_CAST(ms_ecall_load_owner_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sealed_owner_private_key = ms->ms_sealed_owner_private_key;
	int _tmp_sealed_key_len = ms->ms_sealed_key_len;
	size_t _len_sealed_owner_private_key = _tmp_sealed_key_len;
	char* _in_sealed_owner_private_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_owner_private_key, _len_sealed_owner_private_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_owner_private_key != NULL && _len_sealed_owner_private_key != 0) {
		_in_sealed_owner_private_key = (char*)malloc(_len_sealed_owner_private_key);
		if (_in_sealed_owner_private_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_sealed_owner_private_key, _tmp_sealed_owner_private_key, _len_sealed_owner_private_key);
	}

	ms->ms_retval = ecall_load_owner_key((const char*)_in_sealed_owner_private_key, _tmp_sealed_key_len);
err:
	if (_in_sealed_owner_private_key) free((void*)_in_sealed_owner_private_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_seal_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_seal_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_seal_state_t* ms = SGX_CAST(ms_ecall_seal_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sealed_state = ms->ms_sealed_state;
	int* _tmp_sealed_state_len = ms->ms_sealed_state_len;
	size_t _len_sealed_state_len = sizeof(int);
	int* _in_sealed_state_len = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_state_len, _len_sealed_state_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_state_len != NULL && _len_sealed_state_len != 0) {
		_in_sealed_state_len = (int*)malloc(_len_sealed_state_len);
		if (_in_sealed_state_len == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_state_len, _tmp_sealed_state_len, _len_sealed_state_len);
	}

	ms->ms_retval = ecall_seal_state(_tmp_sealed_state, _in_sealed_state_len);
err:
	if (_in_sealed_state_len) {
		memcpy(_tmp_sealed_state_len, _in_sealed_state_len, _len_sealed_state_len);
		free(_in_sealed_state_len);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_state_t* ms = SGX_CAST(ms_ecall_load_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sealed_state = ms->ms_sealed_state;
	int _tmp_sealed_state_len = ms->ms_sealed_state_len;
	size_t _len_sealed_state = _tmp_sealed_state_len;
	char* _in_sealed_state = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_state, _len_sealed_state);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_state != NULL && _len_sealed_state != 0) {
		_in_sealed_state = (char*)malloc(_len_sealed_state);
		if (_in_sealed_state == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_sealed_state, _tmp_sealed_state, _len_sealed_state);
	}

	ms->ms_retval = ecall_load_state((const char*)_in_sealed_state, _tmp_sealed_state_len);
err:
	if (_in_sealed_state) free((void*)_in_sealed_state);

	return status;
}

static sgx_status_t SGX_CDECL sgx_deal_with_deposit_tx(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_deal_with_deposit_tx_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_deal_with_deposit_tx_t* ms = SGX_CAST(ms_deal_with_deposit_tx_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_sender_address = ms->ms_sender_address;
	int _tmp_sender_addr_len = ms->ms_sender_addr_len;
	size_t _len_sender_address = _tmp_sender_addr_len;
	char* _in_sender_address = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sender_address, _len_sender_address);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sender_address != NULL && _len_sender_address != 0) {
		_in_sender_address = (char*)malloc(_len_sender_address);
		if (_in_sender_address == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_sender_address, _tmp_sender_address, _len_sender_address);
	}

	deal_with_deposit_tx((const char*)_in_sender_address, _tmp_sender_addr_len, ms->ms_amount, ms->ms_block_number);
err:
	if (_in_sender_address) free((void*)_in_sender_address);

	return status;
}

static sgx_status_t SGX_CDECL sgx_deal_with_settlement_tx(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	deal_with_settlement_tx();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[12];
} g_ecall_table = {
	12,
	{
		{(void*)(uintptr_t)sgx_ecall_set_routing_fee, 0},
		{(void*)(uintptr_t)sgx_ecall_set_routing_fee_address, 0},
		{(void*)(uintptr_t)sgx_ecall_settle_routing_fee, 0},
		{(void*)(uintptr_t)sgx_ecall_print_state, 0},
		{(void*)(uintptr_t)sgx_ecall_make_settle_transaction, 0},
		{(void*)(uintptr_t)sgx_ecall_secure_command, 0},
		{(void*)(uintptr_t)sgx_ecall_make_owner_key, 0},
		{(void*)(uintptr_t)sgx_ecall_load_owner_key, 0},
		{(void*)(uintptr_t)sgx_ecall_seal_state, 0},
		{(void*)(uintptr_t)sgx_ecall_load_state, 0},
		{(void*)(uintptr_t)sgx_deal_with_deposit_tx, 0},
		{(void*)(uintptr_t)sgx_deal_with_settlement_tx, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][12];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

