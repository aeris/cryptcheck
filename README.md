# Introduction
CryptCheck is a Ruby toolbox that help anybody to check for cryptography security
level and best practices compliance.

CryptCheck is released under
[AGPLv3+](https://www.gnu.org/licenses/agpl-3.0.en.html) license.

# Preliminary warning
**/!\ This tool use custom weak builds of OpenSSL library and OpenSSL Ruby extension /!\**.

Those builds are cryptographically weaken to be able to test for (very) weak and
today totally deprecated ciphers.

Don’t deploy it on production machine to avoid any security troubles, or use VM
to isolate them !

# Setup
## Ruby
You need a fully operationnal Ruby stack.
Because of the warning above, don’t use your system Ruby.

I recommend to use [RBEnv](https://github.com/sstephenson/rbenv) and it
[Ruby-build](https://github.com/sstephenson/ruby-build) plugin to build a new
ruby environment instead of your system one.

Currently supported Ruby stack is v2.3.0.

## OpenSSL library and Ruby extension
To be able to test for (very) weak ciphers and to have access to DH parameters,
CryptCheck need custom build of OpenSSL library and patched build of OpenSSL Ruby
extension.


Once you have cloned CryptCheck repository, just run `make` inside to
build the needed libraries.

If `make` fails with the following error :
```
make: *** No rule to make target 'lib/libssl.so.1.0.0', needed by 'libs'.  Stop.
```
just run again `make` (if you understand this problem, contact me !).

The built libraries (*libcrypto.so*, *libssl.so* and *openssl.so*) are located
under the *lib* directory.<br/>
CryptCheck use *LD_LIBRARY_PATH* and Ruby load path hack to inject those weaken
libraries instead of the system ones.

## Ruby dependencies
CryptCheck relies on few Ruby libraries, managed with [Bundler](http://bundler.io/).

To fetch and install them, just run `bundle install`.

# Usage
Simply run the corresponding runner of what you want to test :

 * HTTPS : ```bin/check_https example.org```
 * XMPP : ```bin/check_xmpp example.org```
 * SMTP : ```bin/check_smtp example.org```

If you want more information of what is going on under the hood, run the command
with debug enabled, like ```bin/check_https example.org debug```

## Understanding results
Rank goes from "A+" (perfect) to "F" (very weak).<br/>
"M" means your certificate and your hostname mismatch.<br/>
"T" means your certificate is not issued by a valid root certificate authority.

Only a perfect setup gets a perfect score and a "A" rank :).<br/>
"A" score is based on [RFC 7525](https://tools.ietf.org/html/rfc7525) recommandations.

 * Protocol
   * SSL (v2 and v3) are totally [deprecated](https://tools.ietf.org/html/rfc7568)
     now, because of very serious known vulnerabilities
     ([Poodle](https://www.openssl.org/~bodo/ssl-poodle.pdf)…).
     Using one of them cap your rank to "F".
   * TLSv1 and TLSv1.1 suffer of the
     [Poodle TLS](https://community.qualys.com/blogs/securitylabs/2014/12/08/poodle-bites-tls)
     vulnerability.
   * TLSv1.2 is the only remaining protocol with no known vulnerabilities, so if
     you don’t support it, your rank is cap to "B".
 * Key size
   * If you use certificate key less than 2048 bits, your rank is cap to "B".
 * Ciphers
   * Very weak ciphers, including MD5 hash, anonymous DH parameters, NULL ciphers 
     (yes, it exits…), export ciphers ([Freak](https://freakattack.com/)) or weak 
     ciphers (RC4, DES…) cap your rank to "F".
   * 3DES is considered weak and must be avoided, using it cap your score to "C".

 * Score
   * Protocol score is based on the **weakest** protocol you support :<br/>
     SSLv2 = 0, SSLv3 = 20, TLSv1 = 60, TLSv1.1 = 80, TLSv1.2 = 100.
   * Key score is based on your certificate key size :<br/>
     <512 = 10, <1024 = 20, <2048 = 50, <4096 = 90, ≥4096 = 100.
   * Cipher score is based on the **weakest** cipher you support :<br/>
     0 = 0, <112 = 10, <128 = 50, <256 = 90, ≥256 = 100.
   * Overall score is based on the other scores :<br/>
     overall = 0.3 * protocol + 0.3 * key + 0.4 * cipher

 * Best practices
   * PFS : you gain this flag when you support **only**
     [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)
     ciphers (DHE or ECDHE)
   * HSTS : you gain this flag when you protect yourself with
     [HTTP Strict Transport Security](https://tools.ietf.org/html/rfc6797).
   * Long HSTS : you gain this flag when you support HSTS with a duration of at
     least 6 monthes.

 * Rank
   * Rank is based on your overall score and above caps :<br/>
     <20 = F, <35 = E, <50 = D, <65 = C, <80 = B, ≥80 = A.
   * If you get an "A" and you have all the best practices above, you get "A+".
