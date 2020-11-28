<!--
# rouTEE
-->

# How to set

Using docker whose version is `sgx v2.1.3` .

```
$ docker run -d --device /dev/isgx --device /dev/mei0 -p [port_num]:[port_num] --name [container_name] tozd/sgx:ubuntu-xenial
```

# How to run

```
$ docker exec -t -i [container_name] bash
```

### SGX env. setting:
```
(in docker) $ source /opt/intel/sgxsdk/environment
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
