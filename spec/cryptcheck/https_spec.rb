module CryptCheck::Tls
	describe Https do
		def server(*args, **kargs, &block)
			tls_serv *args, **kargs, &block
		end

		def plain_server(*args, **kargs, &block)
			plain_serv *args, **kargs, &block
		end

		def analyze(*args)
			Https.analyze *args
		end

		# include_examples :analysis
		#
		# describe '#hsts?' do
		# 	it 'has no hsts' do
		# 		grades = server host: '127.0.0.1' do
		# 			analyze '127.0.0.1', 5000
		# 		end
		#
		# 		_, server = expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
		# 		expect(server.hsts?).to be false
		# 	end
		#
		# 	it 'has hsts' do
		# 		process = proc do |socket|
		# 			socket.print [
		# 								 'HTTP/1.1 200 OK',
		# 								 'Strict-transport-security: max-age=31536000; includeSubdomains; preload',
		# 								 'Content-Type: text/plain',
		# 								 'Content-Length: 0',
		# 								 'Connection: close'
		# 						 ].join "\r\n"
		# 		end
		#
		# 		grades = server host: '127.0.0.1', process: process do
		# 			analyze '127.0.0.1', 5000
		# 		end
		#
		# 		_, server = expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
		# 		expect(server.hsts?).to be true
		# 	end
		# end
		#
		# describe '#hsts_long?' do
		# 	it 'has no hsts' do
		# 		grades = server host: '127.0.0.1' do
		# 			analyze '127.0.0.1', 5000
		# 		end
		#
		# 		_, server = expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
		# 		expect(server.hsts_long?).to be false
		# 	end
		#
		# 	it 'has hsts but not long' do
		# 		process = proc do |socket|
		# 			socket.print [
		# 								 'HTTP/1.1 200 OK',
		# 								 "Strict-transport-security: max-age=#{Https::Server::LONG_HSTS-1}; includeSubdomains; preload",
		# 								 'Content-Type: text/plain',
		# 								 'Content-Length: 0',
		# 								 'Connection: close'
		# 						 ].join "\r\n"
		# 		end
		#
		# 		grades = server host: '127.0.0.1', process: process do
		# 			analyze '127.0.0.1', 5000
		# 		end
		#
		# 		_, server = expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
		# 		expect(server.hsts_long?).to be false
		# 	end
		#
		# 	it 'has long hsts' do
		# 		process = proc do |socket|
		# 			socket.print [
		# 								 'HTTP/1.1 200 OK',
		# 								 "Strict-transport-security: max-age=#{Https::Server::LONG_HSTS}; includeSubdomains; preload",
		# 								 'Content-Type: text/plain',
		# 								 'Content-Length: 0',
		# 								 'Connection: close'
		# 						 ].join "\r\n"
		# 		end
		#
		# 		grades = server host: '127.0.0.1', process: process do
		# 			analyze '127.0.0.1', 5000
		# 		end
		#
		# 		_, server = expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
		# 		expect(server.hsts_long?).to be true
		# 	end
		# end
	end
end
