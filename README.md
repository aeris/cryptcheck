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

### Ruby ###

We need few gems:

* logging
* parallel
* ruby-progressbar
* httparty

Or install via bundle:
```
bundle install
```

### Docker ###

SSLCheck need openssl with all options (protocols,ciphers suite, ...) and ruby linked with this version. We provide an docker image

```
docker pull yverry/sslcheck:latest
```

or build the container image yourself:
```
docker build -t sslcheck .
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
docker run -it --rm -v $(pwd)/output:/opt/sslcheck/output yverry/sslcheck:latest /opt/sslcheck/bin/check_https check
```

In output dir you have **check.html**

# Help #

## Add custom CA ##

You can add your own CA like cacert for example:

````
mkdir /usr/local/share/ca-certificates/cacert.org
wget -P /usr/local/share/ca-certificates/cacert.org http://www.cacert.org/certs/root.crt http://www.cacert.org/certs/class3.crt
update-ca-certificates
```
