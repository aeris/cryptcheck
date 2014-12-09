#!/usr/bin/env ruby
#ENV['LD_LIBRARY_PATH'] = '/home/aeris/Workspace/external/sslscan/openssl'
require 'logging'
$:.unshift 'lib'
require 'sslcheck'

Logging.logger.root.appenders = Logging.appenders.stdout
Logging.logger.root.level = :debug

# Server = Class.new SSLCheck::Server do
# 	def initialize
# 		@key = OpenSSL::PKey::RSA.new 2048
# 		name = OpenSSL::X509::Name.parse 'CN=nobody/DC=example'
# 		@cert = OpenSSL::X509::Certificate.new
# 		@cert.version = 3
# 		@cert.serial = 0
# 		@cert.not_before = Time.now
# 		@cert.not_after = Time.now + 3600
# 		@cert.public_key = @key.public_key
# 		@cert.subject = name
#
# 		@supported_ciphers =
# 		{SSLv3: [], TLSv1: [['ECDHE-RSA-AES256-SHA', 'TLSv1/SSLv3', 256, 256], ['DHE-RSA-AES256-SHA', 'TLSv1/SSLv3', 256, 256], ['ECDHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128], ['DHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128]], TLSv1_1: [['ECDHE-RSA-AES256-SHA', 'TLSv1/SSLv3', 256, 256], ['DHE-RSA-AES256-SHA', 'TLSv1/SSLv3', 256, 256], ['ECDHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128], ['DHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128]], TLSv1_2: [['ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256, 256], ['ECDHE-RSA-AES256-SHA384', 'TLSv1/SSLv3', 256, 256], ['ECDHE-RSA-AES256-SHA', 'TLSv1/SSLv3', 256, 256], ['DHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256, 256], ['DHE-RSA-AES256-SHA256', 'TLSv1/SSLv3', 256, 256], ['DHE-RSA-AES256-SHA', 'TLSv1/SSLv3', 256, 256], ['ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1/SSLv3', 128, 128], ['ECDHE-RSA-AES128-SHA256', 'TLSv1/SSLv3', 128, 128], ['ECDHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128], ['DHE-RSA-AES128-GCM-SHA256', 'TLSv1/SSLv3', 128, 128], ['DHE-RSA-AES128-SHA256', 'TLSv1/SSLv3', 128, 128], ['DHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128]]}
# 	 	@prefered_ciphers = {SSLv3: nil, TLSv1: ['ECDHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128], TLSv1_1: ['ECDHE-RSA-AES128-SHA', 'TLSv1/SSLv3', 128, 128], TLSv1_2: ['ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1/SSLv3', 128, 128]}
#
# 		@hsts = 31536000
# 	end
# end
#server = Server.new
#server = SSLCheck::Server.new 'www.cjn.justice.gouv.fr'
#server = SSLCheck::Server.new 'www.capitainetrain.com'
server = SSLCheck::Server.new 'matlink.fr'
p SSLCheck::Grade.new server
exit

hostname, port = ['www.cjn.justice.gouv.fr', 443]
tcp_client = TCPSocket.new hostname, port
ssl_client = OpenSSL::SSL::SSLSocket.new tcp_client
ssl_client.hostname = hostname
p ssl_client.connect


#hostname = 'provaping.com'
#compressions = {}
# existing_methods.each do |method|
# 	next unless supported_methods.include? method
# 	socket_context = OpenSSL::SSL::SSLContext.new method
# 	socket_context.ciphers = %w(ALL:COMPLEMENTOFALL)
# 	tcp_client = TCPSocket.new hostname, port
# 	ssl_client = OpenSSL::SSL::SSLSocket.new tcp_client, socket_context
# 	ssl_client.hostname = hostname
# 	begin
# 		ssl = ssl_client.connect
# 		data = OpenSSL::ASN1.decode(ssl.session.to_der).value.find { |a| a.tag == 11 }
# 		compression = !data.nil?
# 		compressions[method] = compression
# 	rescue OpenSSL::SSL::SSLError => e
# 	end
# end
#p "Compressions", compressions

#hostname = 'espaceclient.groupama.fr' # not supported
# hostname = 'ameli.moncompte.mobi'
# renegociations = {}
# existing_methods.each do |method|
# 	next unless supported_methods.include? method
# 	socket_context = OpenSSL::SSL::SSLContext.new method
# 	socket_context.ciphers = %w(ALL:COMPLEMENTOFALL)
# 	tcp_client = TCPSocket.new hostname, port
# 	ssl_client = OpenSSL::SSL::SSLSocket.new tcp_client, socket_context
# 	ssl_client.hostname = hostname
# 	begin
# 		ssl = ssl_client.connect
# 		p ssl
# 		#data = OpenSSL::ASN1.decode(ssl.session.to_der).value.find { |a| a.tag == 11 }
# 	rescue OpenSSL::SSL::SSLError => e
# 	end
# end
# p "Renegociations", renegociations
