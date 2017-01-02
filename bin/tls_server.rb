#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'openssl'
require 'socket'
require 'cryptcheck'

::CryptCheck::Logger.level = ENV['LOG'] || :info

OpenSSL::PKey::EC.send :alias_method, :private?, :private_key?

# [512, 768, 1024, 2048, 3072, 4096].each do |s|
# 	file = "config/rsa-#{s}.pem"
# 	unless File.exists? file
# 		puts :rsa, s
# 		dh = OpenSSL::PKey::RSA.new s
# 		File.write file, dh.to_pem
# 	end
#
# 	file = "config/dh-#{s}.pem"
# 	unless File.exists? file
# 		puts :dh, s
# 		dh = OpenSSL::PKey::DH.new s
# 		File.write file, dh.to_pem
# 	end
# end
# exit

def certificate(key)
	CryptCheck::Logger.info 'Generating certificate'
	cert            = OpenSSL::X509::Certificate.new
	cert.version    = 2
	cert.serial     = rand 2**(20*8-1) .. 2**(20*8)
	cert.not_before = Time.now
	cert.not_after  = Time.now + 365*24*60*60

	cert.public_key = case key
						  when OpenSSL::PKey::EC
							  curve             = key.group.curve_name
							  public            = OpenSSL::PKey::EC.new curve
							  public.public_key = key.public_key
							  public
						  else
							  key.public_key
					  end

	name         = OpenSSL::X509::Name.parse 'CN=localhost'
	cert.subject = name
	cert.issuer  = name

	extension_factory                     = OpenSSL::X509::ExtensionFactory.new nil, cert
	extension_factory.subject_certificate = cert
	extension_factory.issuer_certificate  = cert

	cert.add_extension extension_factory.create_extension 'basicConstraints', 'CA:TRUE', true
	cert.add_extension extension_factory.create_extension 'keyUsage', 'keyEncipherment, dataEncipherment, digitalSignature,nonRepudiation,keyCertSign'
	cert.add_extension extension_factory.create_extension 'extendedKeyUsage', 'serverAuth, clientAuth'
	cert.add_extension extension_factory.create_extension 'subjectKeyIdentifier', 'hash'
	cert.add_extension extension_factory.create_extension 'authorityKeyIdentifier', 'keyid:always'
	cert.add_extension extension_factory.create_extension 'subjectAltName', 'DNS:localhost'

	cert.add_extension OpenSSL::X509::Extension.new '1.3.6.1.5.5.7.1.24', '0', true

	cert.sign key, OpenSSL::Digest::SHA512.new
	CryptCheck::Logger.info 'Certificate generated'
	cert
end

key = OpenSSL::PKey::RSA.new File.read 'config/rsa-2048.pem'
#key = OpenSSL::PKey::EC.new('secp521r1').generate_key
cert = certificate key

CryptCheck::Logger.info 'Starting server'

context = OpenSSL::SSL::SSLContext.new
#context = OpenSSL::SSL::SSLContext.new :SSLv3
#context         = OpenSSL::SSL::SSLContext.new :TLSv1_1
context.cert    = cert
context.key     = key
context.ciphers = ARGV[0] || 'ECDHE+AESGCM'

dh                      = OpenSSL::PKey::DH.new File.read 'config/dh-4096.pem'
context.tmp_dh_callback = proc { dh }
#context.ecdh_curves = CryptCheck::Tls::Server::SUPPORTED_CURVES.join ':'
#context.ecdh_curves = 'secp384r1:secp521r1:sect571r1'
context.ecdh_curves     = 'secp384r1'
#ecdh = OpenSSL::PKey::EC.new('secp384r1').generate_key
#context.tmp_ecdh_callback = proc { ecdh }

host, port = '::', 5000
tcp_server              = TCPServer.new host, port
tls_server              = OpenSSL::SSL::SSLServer.new tcp_server, context
::CryptCheck::Logger.info "Server started on #{host}:#{port}"

loop do
	begin
		connection = tls_server.accept

		method = connection.ssl_version

		dh = connection.tmp_key
		cipher = connection.cipher
		cipher = CryptCheck::Tls::Cipher.new method, cipher, dh
		states = cipher.states
		text   = %i(critical error warning good perfect best).collect do |s|
			states[s].collect { |t| t.to_s.colorize s }.join ' '
		end.reject &:empty?
		text   = text.join ' '

		dh     = dh ? " (#{'PFS'.colorize :good} : #{CryptCheck::Tls.key_to_s dh})" : ''
		CryptCheck::Logger.info { "#{CryptCheck::Tls.colorize method} / #{cipher.colorize}#{dh} [#{text}]" }

		data       = connection.gets
		if data
			CryptCheck::Logger.info data
		end
		connection.puts 'HTTP/1.1 200 OK'
		connection.puts 'Strict-Transport-Security: max-age=31536000'
		connection.close
	rescue OpenSSL::SSL::SSLError, SystemCallError
	end
end
