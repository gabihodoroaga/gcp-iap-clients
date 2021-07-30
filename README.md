# gcp-iap-clients

This is a list of examples of how to access Identity-Aware Proxy (IAP)-secured 
resource. There is also a blog post related to this
subject here [GCP IAP Clients](https://hodo.dev/posts).

## Motivation

Google provides client libraries and excellent documentation for most of the
programing languages (C#, Go, Java, Nodejs, PHP, Python, Ruby), you can find out 
more from here [Identity-Aware Proxy - Programmatic authentication](https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_a_service_account). But, there are missing
languages like C, C++ or frameworks like Qt and all these libraries came with
dependencies. This project was created for the situation where you cannot or you
don't want to use the client libraries provided by Google.


## Clients

The following examples are available:


Name                 | Link              | Description
-------------------- | ----------------- | -------------
C no OpenSSL         | TODO
C with OpenSSL       | [c_openssl](c_openssl)
Nodejs               | [nodejs](nodejs)
Python               | [python](python)
Qt without OpenSSL   | [qt](qt)
Qt with OpenSSL      | TODO

You can find specific documentation in each project folder.

