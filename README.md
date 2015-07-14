# SSLCheck #

## Introduction ##

SSLCheck perform a deep SSL/TLS scan.
He can check

Certificate:

* Key size
* SHA1 sig

Protocols :
* SSLv2
* SSLv3
* TLSv1 v1.1 v1.2

Ciphers:
* Strength
* MD5
* RC4/DES
* 3DES

Best practice:
* HSTS
* PFS

With all this informations sslcheck provide an HTML output and a grade for each hostname:

Grade | Status
------|-------
A+ | Green
A-|Green
A|Green
B|Warning
C|Warning
T|Critical
M|Critical


## Installations ##

### Docker ###

SSLCheck need openssl with all options (protocols,ciphers suite, ...) and ruby linked with this version. We provide an docker image

Build the container image:
```
docker build -t sslcheck/1.0 .
```

## Use ##

In input sslcheck need a list like **check.yml**:

```
- description: Add an description
  hostnames:
  - www.example.com
  - mail.foo.bar
  - ...
```
run it:
```
docker run -it --rm -v $(pwd)/output:/opt/sslcheck/output sslcheck/1.0 /opt/sslcheck/bin/check_https check
```

In output dir you have an **check.html**
