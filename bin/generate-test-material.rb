#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'openssl'
require 'socket'
require 'cryptcheck'

LOG       = ::CryptCheck::Logger

OpenSSL::PKey::EC.send :alias_method, :private?, :private_key?

CA_KEY_USAGE            = %w(keyCertSign cRLSign)
CA_EXTENDED_KEY_USAGE   = []
CA_NETSCAPE_CERT_TYPE = %w(sslCA)
RSA_KEY_USAGE           = %w(digitalSignature)
ECDSA_KEY_USAGE         = %w(digitalSignature)
CERT_EXTENDED_KEY_USAGE = %w(serverAuth)
CERT_NETSCAPE_CERT_TYPE = %w(server)


def certificate(key, subject, san: %w(DNS:localhost),
				from: Time.utc(2000, 1, 1), to: Time.utc(2001, 1, 1),
				issuer: nil, ca: false,
				key_usage: ECDSA_KEY_USAGE, extended_key_usage: CERT_EXTENDED_KEY_USAGE,
				netscape_cert_type: CERT_NETSCAPE_CERT_TYPE,
				hash: OpenSSL::Digest::SHA512, extensions: [])
	cert            = OpenSSL::X509::Certificate.new
	cert.version    = 3
	cert.serial     = rand 2**63 .. 2**64
	cert.not_before = from if from
	cert.not_after  = to if to

	cert.public_key = case key
						  when OpenSSL::PKey::EC
							  curve             = key.group.curve_name
							  public            = OpenSSL::PKey::EC.new curve
							  public.public_key = key.public_key
							  public
						  else
							  key.public_key
					  end

	name         = OpenSSL::X509::Name.parse subject
	cert.subject = name

	issuer       = { cert: cert, key: key } unless issuer
	cert.issuer  = issuer[:cert].subject

	extension_factory                     = OpenSSL::X509::ExtensionFactory.new nil, cert
	extension_factory.subject_certificate = cert
	extension_factory.issuer_certificate  = issuer[:cert]

	cert.add_extension extension_factory.create_extension 'basicConstraints', "CA:#{ca.to_s.upcase}", true
	cert.add_extension extension_factory.create_extension 'keyUsage', key_usage.uniq.join(','), true unless key_usage.empty?
	cert.add_extension extension_factory.create_extension 'extendedKeyUsage', extended_key_usage.uniq.join(','), true unless extended_key_usage.empty?
	cert.add_extension extension_factory.create_extension 'nsCertType', netscape_cert_type.uniq.join(',') unless netscape_cert_type.empty?
	cert.add_extension extension_factory.create_extension 'subjectKeyIdentifier', 'hash'
	cert.add_extension extension_factory.create_extension 'authorityKeyIdentifier', 'keyid:always'
	cert.add_extension extension_factory.create_extension 'subjectAltName', san.uniq.join(',') unless san.empty?

	extensions.each { |e| cert.add_extension e }

	cert.sign issuer[:key], hash.new

	cert
end

def generate_dh(size)
	filename = "spec/resources/dh-#{size}.pem"
	return if File.exist? filename
	LOG.info "Generate dh-#{size}"
	File.write filename, OpenSSL::PKey::DH.new(size).to_pem
end

def generate_material(name, key, cert)
	key_file = "spec/resources/#{name}.pem"
	key      = if File.exists?(key_file)
				   OpenSSL::PKey.read File.read key_file
			   else
				   LOG.info "Generate #{name} key"
				   key = key.call
				   File.write key_file, key.to_pem
				   key
			   end

	cert_file = "spec/resources/#{name}.crt"
	cert      = if File.exist?(cert_file)
					OpenSSL::X509::Certificate.new File.read cert_file
				else
					LOG.info "Generate #{name} cert"
					cert = cert.call key
					File.write cert_file, cert.to_pem
					cert
				end

	[key, cert]
end

ca_key, ca_cert = generate_material 'ca',
									-> () { OpenSSL::PKey::EC.new('secp384r1').generate_key },
									-> (k) { certificate k, '/CN=ca', ca: true, key_usage: CA_KEY_USAGE, extended_key_usage: CA_EXTENDED_KEY_USAGE, netscape_cert_type: CA_NETSCAPE_CERT_TYPE }

intermediate_key, intermediate_cert = generate_material 'intermediate',
														-> () { OpenSSL::PKey::EC.new('secp384r1').generate_key },
														-> (key) { certificate key, '/CN=intermediate', ca: true, issuer: { cert: ca_cert, key: ca_key }, key_usage: CA_KEY_USAGE, extended_key_usage: CA_EXTENDED_KEY_USAGE, netscape_cert_type: CA_NETSCAPE_CERT_TYPE }
issuer                              = { cert: intermediate_cert, key: intermediate_key }

[512, 768, 1024, 2048, 3072, 4096].each do |s|
	generate_material "rsa-#{s}",
					  -> () { OpenSSL::PKey::RSA.new s },
					  -> (key) { certificate key, "/CN=rsa-#{s}", issuer: issuer, key_usage: RSA_KEY_USAGE }
	generate_dh s
end

CryptCheck::Tls::Curve.each do |c|
	c = c.name
	generate_material "ecdsa-#{c}",
					  -> () { OpenSSL::PKey::EC.new(c).generate_key },
					  -> (key) { certificate key, "/CN=ecdsa-#{c}", issuer: issuer }
end

generate_material 'self-signed',
				  -> { OpenSSL::PKey::EC.new('prime256v1').generate_key },
				  -> (key) { certificate key, '/CN=self-signed', ca: true,
										 key_usage:                  CA_KEY_USAGE+ECDSA_KEY_USAGE,
										 extended_key_usage:         CA_EXTENDED_KEY_USAGE + CERT_EXTENDED_KEY_USAGE,
										 netscape_cert_type: CA_NETSCAPE_CERT_TYPE + CERT_NETSCAPE_CERT_TYPE }

# Require patched OpenSSL to be able to issue MD5 certificates
generate_material 'md5',
				  -> { OpenSSL::PKey::EC.new('prime256v1').generate_key },
				  -> (key) { certificate key, '/CN=md5', issuer: issuer, hash: OpenSSL::Digest::MD5 }

# Require patched OpenSSL to be able to issue SHA1 certificates
generate_material 'sha1',
				  -> { OpenSSL::PKey::EC.new('prime256v1').generate_key },
				  -> (key) { certificate key, '/CN=sha1', issuer: issuer, hash: OpenSSL::Digest::SHA1 }

must_staple = OpenSSL::X509::Extension.new '1.3.6.1.5.5.7.1.24', '0', true
generate_material 'must-staple',
				  -> () { OpenSSL::PKey::EC.new('prime256v1').generate_key },
				  -> (key) { certificate key, '/CN=must-staple', issuer: issuer, extensions: [must_staple] }
