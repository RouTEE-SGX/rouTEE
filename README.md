# RouTEE

This repository contains the implementation of **RouTEE: Secure, Scalable, and Efficient Off-Chain Payments using Trusted Execution Environments**, as described in our paper.

## Table of Contents
- [Getting Started](#getting-started)
  - [Dependencies](#dependencies)
  - [Setting Up the SGX Docker Container](#setting-up-the-sgx-docker-container)
    - [Basic Setup (for machines not supporting SGX)](#basic-setup-for-machines-not-supporting-sgx)
    - [Standard Hardware Mode Setup (for machines supporting SGX)](#standard-hardware-mode-setup-for-machines-supporting-sgx)
  - [Setting Up the SGX Environment](#setting-up-the-sgx-environment)
  - [Building RouTEE](#building-routee)
  - [Running RouTEE](#running-routee)
- [User Commands](#user-commands)
  - [Installation](#installation)
  - [Generating Commands](#generating-commands)
    - [Example Commands](#example-commands)
- [Client Operations](#client-operations)
  - [Running `client.py`](#running-clientpy)
- [Host Operations](#host-operations)
  - [Running `host.py`](#running-hostpy)
- [Running Examples](#running-examples)
  - [Step 1: Generate All Scripts](#step-1-generate-all-scripts)
  - [Step 2: Execute RouTEE and `client.py`](#step-2-execute-routee-and-clientpy)
  - [Step 3: Execute RouTEE and `host.py`](#step-3-execute-routee-and-hostpy)





## Getting Started

### Dependencies

RouTEE has been tested on **Ubuntu 18.04.2 LTS** with **SGX Docker** version `sgx v2.1.3`.

### Setting Up the SGX Docker Container

#### Basic Setup (for machines not supporting SGX)

To set up the SGX Docker container on a machine without SGX support, run the following commands:

```bash
$ docker run -d -p [port_num]:[port_num] --name [container_name] tozd/sgx:ubuntu-xenial
$ docker exec -t -i [container_name] bash
```

This configuration runs SGX in `Simulation` mode, allowing RouTEE to operate on machines that do not support SGX.

#### Standard Hardware Mode Setup (for machines supporting SGX)

If your machine has SGX support and you want to run in `Hardware` mode, follow these steps:

1. Install the [Linux SGX Driver](https://github.com/intel/linux-sgx-driver).

2. Run the SGX Docker container with the following commands:

    ```bash
    $ docker run -d --device /dev/isgx --device /dev/mei0 -p [port_num]:[port_num] --name [container_name] tozd/sgx:ubuntu-xenial
    $ docker exec -t -i [container_name] bash
    ```

    **Note:** If your machine does not have `/dev/mei0`, you can omit the `--device /dev/mei0` option.

### Setting Up SGX Environment

Once inside the Docker container, set up the SGX environment:

```bash
$ source /opt/intel/sgxsdk/environment
```

### Building RouTEE

Before building RouTEE, ensure to configure the `SERVER_IP` and `SERVER_PORT` in `App/routee.h`.

If you wish to run RouTEE in `Hardware` mode, you need to modify both `sgx_u.mk` and `sgx_t.mk` files before building. In each file, uncomment this line:

```makefile
SGX_MODE ?= HW
```

Then, proceed with the following commands to build RouTEE:

```bash
$ cd
$ git clone https://github.com/RouTEE-SGX/rouTEE.git --branch artifact
$ cd rouTEE
$ sudo apt-get install libcurl4-openssl-dev libssl-dev
$ cd tee/Enclave/libs/bitcoin/secp256k1
$ chmod +x autogen.sh && ./autogen.sh && ./configure
$ cd ../../../..
$ make
```

### Running RouTEE

After the build is complete, run RouTEE with:

```bash
$ ./routee
```

You should see the message when RouTEE is ready: `Waiting for connections ...`.





## User Commands

### Installation

For working with user commands, we used **Python 3.7.4** and **pip 21.3.1**.

```bash
$ sudo apt update
$ sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev
$ wget https://www.python.org/ftp/python/3.7.4/Python-3.7.4.tgz
$ tar xvfz Python-3.7.4.tgz 
$ cd Python-3.7.4
$ ./configure 
$ make
$ sudo make install

$ sudo apt-get install python3-pip
$ python3 -m pip install pip==21.3.1
```

Once Python and pip are installed, set up the environment with:

```bash
$ cd tee/client
$ pip3 install -r requirements.txt
```

### Generating Commands

We provide a script to generate commands for different purposes. Use the following command:

```bash
$ python3 generate_script.py
```

You will be prompted to choose the type of script to generate. The output will be saved in the `scripts/` directory:

- `addressList`: a list of Bitcoin addresses
- `script*`: plain commands
- `signed*`: encrypted commands containing cryptographic signatures

#### Example Commands

- **Create New Private/Public Keys:**

  ```bash
  $ python3 generate_script.py 1 <keyNum>
  ```

  Generates public/private keys in the `keys/` directory. These keys are used to create cryptographic signatures and to validate users.

- **Generate Bitcoin Addresses:**

  ```bash
  $ python3 generate_script.py 2 <addrNum>
  ```

  Generates the `addressList` file.

- **Add New Users:**

  ```bash
  $ python3 generate_script.py 3 <userNum>
  ```

  Generates `scriptAddUser_{userNum}` and `signedAddUser_{userNum}` files to register a user. (***add_user*** operations)

- **Deposit Funds:**

  ```bash
  $ python3 generate_script.py 4 <totalUserNum> <depositNum>
  ```

  Generates `scriptAddDeposit_{totalUserNum}_{depositNum}` and `signedAddDeposit_{totalUserNum}_{depositNum}` files. (***add_deposit*** operations)

- **Request Payments:**

  ```bash
  $ python3 generate_script.py 5 <totalUserNum> <paymentNum> <batchSize>
  ```

  Generates `scriptPayment_{totalUserNum}_{paymentNum}_{batchSize}` and `signedPayment_{totalUserNum}_{paymentNum}_{batchSize}` files.  (***payment*** operations)

- **Request Settlements:**

  ```bash
  $ python3 generate_script.py 6 <totalUserNum> <settlementNum>
  ```

  Generates `scriptSettlement_{totalUserNum}_{settlementNum}` and `signedSettlement_{totalUserNum}_{settlementNum}` files. (***settlement*** operations)

- **Update Boundary Blocks:**

  ```bash
  $ python3 generate_script.py 7 <totalUserNum> <updateNum> <maxBlockNum>
  ```

  Generates `scriptUpdate_{totalUserNum}_{updateNum}_{maxBlockNum}` and `signedUpdate_{totalUserNum}_{updateNum}_{maxBlockNum}` files. (***update_boundary_block*** operations)

- **Generate All Commands:**

  ```bash
  $ python3 generate_script.py 0 <userNum> <depositNum> <paymentNum> <batchSize> <settlementNum> <updateNum> <maxBlockNum>
  ```

  Generates all the command files mentioned above.





## Client Operations

### Running `client.py`

Configure `SERVER_IP` and `SERVER_PORT` in `client/routee_configs.py`. Then, start the client console:

```bash
$ python3 client.py
```

You can input file names generated by `generate_script.py`. Ensure the ***add_user*** script is executed first.





## Host Operations

### Running `host.py`

Configure `SERVER_IP` and `SERVER_PORT` in `client/routee_configs.py` before starting the host. Run the host with:

```bash
$ python3 host.py <roundInterval> <roundNum>
```

This command will execute the ***process_round*** operation `roundNum` times, with each round spaced by `roundInterval` seconds. It commits all pending payments and creates a backup file named `state_sealed` to securely preserve the state. If RouTEE is rebooted, it will automatically load the sealed state from the backup file, if available.





## Running Examples

### Step 1: Generate All Scripts

To generate all necessary scripts for RouTEE, run the following command:

```bash
$ python3 generate_script.py 
```

You will be prompted to select the type of script to generate. To generate all scripts, select option `0`:

```plaintext
Which script do you want to make (0: all / 1: makeNewKeys / 2: makeNewAddresses / 3: makeAddUsers / 4: makeAddDeposits / 5: makePayments / 6: makeSettlements / 7: makeUpdateBoundaryBlocks): [0]
```

Next, provide the required parameters:

```plaintext
How many users in RouTEE: [10]
How many manager addresses to get: [5]
How many RouTEE payments to execute: [5]
  How many receivers per payment (batch size): [1]
How many RouTEE settlements to execute: [5]
How many RouTEE boundary block updates to execute: [5]
  Max block number in RouTEE: [100]
```

The script will generate the following outputs:

```plaintext
100%|██████████████████████████████████████████████████████████████████████████████████████████████| 10/10 [00:05<00:00,  1.89it/s]
  -> Generated private & public keys
  -> Generated addressList
  -> Generated scriptAddUser_10 & signedAddUser_10
  -> Generated scriptAddDeposit_10_5 & signedAddDeposit_10_5
  -> Generated scriptPayment_10_5_1 & signedPayment_10_5_1
  -> Generated scriptSettlement_10_5 & signedSettlement_10_5
  -> Generated scriptUpdate_10_5_100 & signedUpdate_10_5_100
Elapsed time: 0:00:23.780391
```

### Step 2: Execute RouTEE and `client.py`

#### Window 1: RouTEE

Start the RouTEE server with:

```bash
$ ./routee
```

You should see output similar to the following:

```plaintext
Start initializing RouTEE
Latest block number in RouTEE: 52560
Pending deposit requests number in RouTEE: 10000
Finish initializing RouTEE

Try to load sealed state
  There is no sealed state. Starting a new instance of RouTEE
  Elapsed time for state unsealing: 6 us (0 ms)
Waiting for connections ...
```

#### Window 2: Client

Run the client with:

```bash
$ python3 client.py 
```

You should see the client successfully connect to RouTEE:

```plaintext
successfully connect to RouTEE
start
thread count: 15

input command: 
```

First, execute `scriptAddUser_10`, then input the other scripts generated earlier. This will result in an output similar to the one described below.

```plaintext
<Window 1: RouTEE>

ADD_USER success: user index: 0 / settle address: mnDjFN8szvqJmGghsQiFsNUMhUYiNi2dZx
ADD_USER success: user index: 1 / settle address: mtGyqYE63sUiyLmDyyomF2dV6WSG2h2e24
ADD_USER success: user index: 2 / settle address: mqeb4k13kBCDaXouG6tMwSFq5KvZaVDVv3
ADD_USER success: user index: 3 / settle address: mttypC2ZXeJYjnzCyz3GYFWgckwc84hYut
ADD_USER success: user index: 4 / settle address: mmeQtiPcCZPq5PJBtqXFC9271KGQRPVNmB
ADD_USER success: user index: 5 / settle address: mh33oui6c4uuAyzCSURLokQn1wnCU7U6gC
ADD_USER success: user index: 6 / settle address: miEfboyoH2og4fx18yZ15ZqTLmJKa5T3r1
ADD_USER success: user index: 7 / settle address: mvUcaNz66Qh95xQ4z4mdrdgmVhhCx1tHBE
ADD_USER success: user index: 8 / settle address: mzAUPmbqg4JDJLUMbhyAFo4L2gbxQ5DER9
ADD_USER success: user index: 9 / settle address: n1qNfyigXyDZT7XfXLJRxfcBiBeq5GFSEV
ADD_DEPOSIT success: random manager keyid: f59bb90dca83439500a908d332ff839a66bef63e / block number: 52560
ADD_DEPOSIT success: random manager keyid: 12e8adac0b660eda9b5105c1e785420fc25b8f14 / block number: 52560
ADD_DEPOSIT success: random manager keyid: ff8c1262247384c9234ec4347d8e46143e3a3b3f / block number: 52560
ADD_DEPOSIT success: random manager keyid: ae25378a289728cfd40ee9371479ad42280a61dc / block number: 52560
ADD_DEPOSIT success: random manager keyid: ee81be7270f14982c040987a42c49e431c15fa4c / block number: 52560
PAYMENT success: user 9 send 16 satoshi to user 7 (routing fee: 10)
PAYMENT success: user 4 send 66 satoshi to user 9 (routing fee: 8)
PAYMENT success: user 8 send 56 satoshi to user 4 (routing fee: 8)
PAYMENT success: user 0 send 97 satoshi to user 5 (routing fee: 6)
PAYMENT success: user 0 send 95 satoshi to user 9 (routing fee: 3)
SETTLEMENT success: user index: 1 / amount: 100 / fee: 10
SETTLEMENT success: user index: 7 / amount: 100 / fee: 10
SETTLEMENT success: user index: 2 / amount: 100 / fee: 10
SETTLEMENT success: user index: 1 / amount: 100 / fee: 10
SETTLEMENT success: user index: 8 / amount: 100 / fee: 10
UPDATE_BOUNDARY_BLOCK success: user 2 update boundary block number to 48
UPDATE_BOUNDARY_BLOCK success: user 9 update boundary block number to 60
UPDATE_BOUNDARY_BLOCK success: user 1 update boundary block number to 7
UPDATE_BOUNDARY_BLOCK success: user 5 update boundary block number to 81
UPDATE_BOUNDARY_BLOCK success: user 1 update boundary block number to 84
```
```plaintext
<Window 2: Client>

input command: [scriptAddUser_10]
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
run script elapsed time: 0:00:00.655380

input command: [scriptAddDeposit_10_5]
  result: f59bb90dca83439500a908d332ff839a66bef63e
  result: 12e8adac0b660eda9b5105c1e785420fc25b8f14
  result: ff8c1262247384c9234ec4347d8e46143e3a3b3f
  result: ae25378a289728cfd40ee9371479ad42280a61dc
  result: ee81be7270f14982c040987a42c49e431c15fa4c
run script elapsed time: 0:00:00.350458

input command: [scriptPayment_10_5_1]
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
run script elapsed time: 0:00:00.348292

input command: [scriptSettlement_10_5]
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
run script elapsed time: 0:00:00.351632

input command: [scriptUpdate_10_5_100]
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
  result: SUCCESS
run script elapsed time: 0:00:00.356322
```

### Step 3: Execute RouTEE and `host.py`

#### Window 3: Host

Run the host process with:

```bash
$ python3 host.py 2 3
```

The output will show `3` rounds being processed, each at `2`-second intervals. This will result in an output similar to the one described below.

```plaintext
<Window 1: RouTEE>

process round executed
Elapsed time for processing round: 258 us (0 ms)

process round executed
Elapsed time for processing round: 334 us (0 ms)

process round executed
Elapsed time for processing round: 192 us (0 ms)
```

```plaintext
<Window 3: host.py>

Successfully connected to RouTEE
  Round interval: 2 sec
  Number of rounds to run: 3

Round 1
Received: SUCCESS
Measured interval: 2.000000256 sec

Round 2
Received: SUCCESS
Measured interval: 2.000000089 sec

Round 3
Received: SUCCESS
Measured interval: 2.000000174 sec

Finish
```
