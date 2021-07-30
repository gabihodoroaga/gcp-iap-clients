# Access IAP-secured resources using C and OpenSSL

This is an example of how to access Google IAP-secured resources using 
C and OpenSSL.

## Solution overview

![OAuth flow](../.doc/oauth_flow.png)

## Build and run 

To build the project you need to download and build all the dependencies (OpenSSL and Curl).

Run the following scripts from this folder.

### OpenSSL

```bash
cd ..
curl -OL https://www.openssl.org/source/openssl-1.1.1h.tar.gz
tar -xvzf openssl-1.1.1h.tar.gz && rm openssl-1.1.1h.tar.gz 
cd openssl-1.1.1h
./configure --prefix=$PWD/.openssl
make
make install
cd ../c_openssl
```

### Curl

```bash
cd ..
curl -OL https://curl.se/download/curl-7.77.0.tar.gz
tar -xzvf curl-7.77.0.tar.gz && rm curl-7.77.0.tar.gz
cd curl-7.77.0
./configure --prefix=$PWD/.curl --with-openssl=../openssl-1.1.1h/.openssl
make
make install
cd ../c_openssl
```

### Build example

```bash
make
```

### Run

```bash
obj/main "key.json" "audience" "https://example.com"
```

You will need to provide a the key.json file and the audience.

You can follow the tutorial from here [IAP on GKE](https://hodo.dev/posts/post-26-gcp-iap/)
to have a working example of a IAP-secured resource.
