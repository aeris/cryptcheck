## Introduction
cryptcheck is a set of ruby scripts that help one to check cryptography level.  


## Pre-requisite
cryptcheck requires ruby version 2 and above to run.  
The script also require a set of library, which we will install with ```bundler```  

In order to get the script to work, one needs to recompile openssl with this [patch](patch).    
The patch provide a view into weak cipher and DH param.  

### Building openssl
The goal here is to fetch and recompile openssl support for ruby
From within this directory, run the following:
```
make
```
If the make fails with the following error:
```
make: *** No rule to make target 'lib/libssl.so.1.0.0', needed by 'libs'.  Stop.
```
The solution is to run make again, the second run will work:
```
make; make 
```

### Instaling libraries
The scripts rely on the availability of a few library.  
From within this directory, run the following:
```
bundle install
```

## Running the scripts
Checking https:  
```
bin/check_https google.com
```
Checking xmpp:  
```
bin/check_xmpp google.com
```
Checking smtp:  
```
bin/check_smtp google.com
```

## Understanding results
The view taken by the author is that only a perfect setup gets a perfect score.  
If you tested your infrastructure, you might have a few question.  

### How can I improve my score: Protocol
To improve your score in protocol, you need to make sure you don't use any protocol that have been proven unsecure or weak.  
Currently 100 is done with TLS1.2 enabled and TLS1.1, TLS1.0, SSLv3 and SSLv2 disabled.  
It is important to know that all browser and all device will not have TLS1.2 available to them.  

### How can I improve my score: Key Exchange
To improve your Key exchange, you need to make sure your certificate is strong enough since the strengh of the certificate will dictate the strenght of the dh-param you cn use.  
A certificate of 4096 bit is what you currently need to have 100.  

### How can I improve my score: Key Exchange
To improve your score, you need to make sure you don't use any ciphers that have been proven unsecure or weak.  


### Best practices
Some of the best practices are also tested.  
They are properties of the crypto or mecahnism to improve the robustness of the system:  
- PFS: perfect forward secrecy  
- HSTS: HTTP Strict Transport Security   
- HSTS_LONG: HTTP Strict Transport Security with over X month  
- HPKP: HTTP Public Key Pinning  


## Going further
Here is a list of ressources that will help you improve your score and or your understanding.

### https
A good start would be to compare yours with the [Mozilla SSL Configuration Generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/)
 
## Going deeper
If you want to go deeper in the understanding of the what is going on under the hood, run the command with debug like so:
```
LD_LIBRARY_PATH=lib bin/check_https google.com debug
```
