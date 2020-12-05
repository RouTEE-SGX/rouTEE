<!--
# rouTEE
-->

## How to set

Using docker whose version is `sgx v2.1.3` .

```
$ docker run -d --device /dev/isgx --device /dev/mei0 -p [port_num]:[port_num] --name [container_name] tozd/sgx:ubuntu-xenial
```

## How to run `rouTEE`

```
$ docker exec -t -i [container_name] bash
```

### SGX env. setting:
```
(in docker)$ source /opt/intel/sgxsdk/environment
```

### git clone rouTEE & env. setting

```
$ git clone https://github.com/ElectricPanda/rouTEE.git [--branch alpha]
$ cd rouTEE
$ sudo apt-get install libcurl4-openssl-dev libssl-dev
$ cd tee/Enclave/libs/bitcoin/secp256k1
$ chmod +x autogen.sh && ./autogen.sh && ./configure
$ cd ../../../..
$ make
```

### Run rouTEE

```
$ ./rouTEE
```

You can see the msg `Waiting for connections ...` .

## How to run `client.py`

```
$ cd tee/client
$ mkdir key
$ mkdir experiment
$ pip3 install -r requirements.txt
```

### Make scripts
```
$ cd scripts
$ python3 makeScript.py
$ cd ..
```

### Run `client.py` console
```
$ python3 client.py
```

### Run `client.py` with script
```
$ python3 client.py script*
```

<!--
### Run `client.py` with pre-signed script
```
$ python3 client.py signed*
```
-->

### Run `client.py` with script line by line
```
$ python3 client.py < script*
```

The second way, running with line by line, is more prefered.


### Run `client.py` with pre-signed script line by line
```
$ python3 client.py < signed* signed
```

<!--
### Run `client.py` parallel
```
$ sh runScripts.sh <rounds>
```
* MUST set <rounds> .
-->
