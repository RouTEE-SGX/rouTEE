######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_PRERELEASE ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
	$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2 -DNDEBUG
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
#	SGX_COMMON_CFLAGS += -DSGX_ATTEST
endif

Crypto_Library_Name := sgx_tcrypto

routee_Cpp_Files := $(shell find Enclave/ -type f -name '*.cpp')
routee_C_Files := $(shell find Enclave/ -type f -name '*.c')
routee_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/stdc++ -IEnclave/ -IEnclave/libs/ -IEnclave/libs/bitcoin -IEnclave/libs/bitcoin/config -IEnclave/libs/bitcoin/univalue/include -IEnclave/libs/bitcoin/secp256k1/ -IEnclave/libs/bitcoin/secp256k1/include/ -IEnclave/libs/ -IEnclave/libs/remote_attestation

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(routee_Include_Paths) -fno-builtin-printf -I. -DINTEL_SGX_ENV -DHAVE_CONFIG_H -Wreturn-type -Wextra
routee_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags)
routee_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++ -fno-builtin-printf -I.

routee_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive -Wl,--allow-multiple-definition \
    -Wl,--start-group -LEnclave/libs/mbedtls -lmbedtls_sgx_t -lsgx_tstdc -lsgx_tstdcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
    -Wl,--defsym,__ImageBase=0 \
    -Wl,--version-script=Enclave/routee.lds \

routee_Cpp_Objects := $(routee_Cpp_Files:.cpp=.o)
routee_C_Objects := $(routee_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: routee.so
	@echo "Build enclave routee.so  [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the routee.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo 


else
all: routee.signed.so
endif



run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## routee Objects ########

Enclave/routee_t.c: $(SGX_EDGER8R) ./Enclave/routee.edl
	@cd ./Enclave && $(SGX_EDGER8R) --trusted ../Enclave/routee.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/routee_t.o: ./Enclave/routee_t.c
	$(CC) $(routee_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	$(CXX) $(routee_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave/%.o: Enclave/%.c
	$(CC) $(routee_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

routee.so: Enclave/routee_t.o $(routee_Cpp_Objects) $(routee_C_Objects)
	$(CXX) $^ -o $@ $(routee_Link_Flags)
	@echo "LINK =>  $@"

routee.signed.so: routee.so
	$(SGX_ENCLAVE_SIGNER) sign -key Enclave/routee_private.pem -enclave routee.so -out $@ -config Enclave/routee.config.xml
	@echo "SIGN =>  $@"
clean:
	@rm -f routee.* Enclave/routee_t.* $(routee_Cpp_Objects) $(routee_C_Objects)
