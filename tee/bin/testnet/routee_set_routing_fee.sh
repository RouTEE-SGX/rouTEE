#!/bin/bash
set -e

# Colour constants
bold=`tput bold`
green=`tput setaf 2`
red=`tput setaf 1`
reset=`tput sgr0`

OWNER_PORT=10000
ALICE_PORT=10001
BOB_PORT=10002

OWNER_ADDR=00000000000000000000000000000owner
ALICE_ADDR=00000000000000000000000000000alice
BOB_ADDR=0000000000000000000000000000000bob

ALICE_TXID=0000000000000000000000000000000000000000000000000000000000000001
BOB_TXID=0000000000000000000000000000000000000000000000000000000000000002

OWNER_LOG=bin/testnet/test/owner.txt
ALICE_LOG=bin/testnet/test/alice.txt
BOB_LOG=bin/testnet/test/bob.txt

../kill.sh

if test -d bin; then cd bin; fi

echo "${bold}Mounting a RAM disk for server output in test directory!${reset}"
if mountpoint -q -- "test"; then
    sudo umount test
fi

rm -r test | true # in case this is the first time being run
mkdir test && sudo mount -t tmpfs -o size=5000m tmpfs test

# Source Intel Libraries
source /opt/intel/sgxsdk/environment

pushd ../../ # go to source directory
echo "${bold}Starting ghost rouTEE enclaves...${reset}"

echo "${bold}Spawning enclave OWNER listening on port $OWNER_PORT in $OWNER_LOG ${reset}"
./teechain ghost -d -p $OWNER_PORT > $OWNER_LOG 2>&1 &
sleep 1

echo -n "${red}Waiting until enclaves are initialized ...!${reset}"
for u in owner; do  #TODO: generalize to multiple parties (not just 4)
    while [ "$(grep -a 'Enclave created' bin/testnet/test/${u}.txt | wc -l)" -eq 0 ]; do
        sleep 0.1
        echo -n "."
    done
done

# Create primaries
./teechain routee_primary -p $OWNER_PORT

# Setup up primaries with number of deposits
./teechain routee_set_routing_fee 20 -p $OWNER_PORT
./teechain routee_set_fee_address $OWNER_ADDR -p $OWNER_PORT

sleep 1

./teechain routee_setup_deposit_request $ALICE_ADDR -p $OWNER_PORT

sleep 1

./teechain routee_print_state -p $OWNER_PORT

sleep 1

./teechain routee_create_channel $ALICE_ADDR $ALICE_TXID 1000 -p $OWNER_PORT

sleep 1

./teechain routee_print_state -p $OWNER_PORT

sleep 1

./teechain routee_do_multihop_payment $ALICE_ADDR $BOB_ADDR 500 20 -p $OWNER_PORT

sleep 1

./teechain routee_print_state -p $OWNER_PORT

./teechain shutdown -p $OWNER_PORT

popd # return to bin directory

../kill.sh
echo "${bold}Looks like the test passed!${reset}"
