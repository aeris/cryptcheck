RSpec.shared_examples :analysis do
	describe '#analyze' do
		it 'return 1 grade with IPv4' do
			grades = server host: '127.0.0.1' do
				analyze '127.0.0.1', 5000
			end

			expect(grades.size).to be 1
			expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
		end

		it 'return 1 grade with IPv6' do
			grades = server host: '::1' do
				analyze '::1', 5000
			end

			expect(grades.size).to be 1
			expect_grade grades, '::1', '::1', 5000, :ipv6
		end

		it 'return 2 grades with hostname (IPv4 & IPv6)' do
			addresses = %w(127.0.0.1 ::1)
			allow(Addrinfo).to receive(:getaddrinfo).with('localhost', nil, nil, :STREAM) do
				addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
			end

			grades = server host: '::' do
				analyze 'localhost', 5000
			end

			expect_grade grades, 'localhost', '127.0.0.1', 5000, :ipv4
			expect_grade grades, 'localhost', '::1', 5000, :ipv6
		end

		it 'return error if DNS resolution problem' do
			allow(Addrinfo).to receive(:getaddrinfo).with('localhost', nil, nil, :STREAM)
									   .and_raise SocketError, 'getaddrinfo: Name or service not known'

			grades = server do
				analyze 'localhost', 5000
			end

			expect_grade_error grades, 'localhost', nil, 5000, 'Unable to resolve localhost'
		end

		it 'return error if analysis too long' do
			stub_const 'CryptCheck::MAX_ANALYSIS_DURATION', 1
			allow(CryptCheck::Tls::Server).to receive(:new) { sleep 2 }

			grades = server do
				analyze 'localhost', 5000
			end

			expect_grade_error grades, 'localhost', '127.0.0.1', 5000,
							   'Too long analysis (max 1 second)'
		end

		it 'return error if unable to connect' do
			addresses = %w(127.0.0.1 ::1)
			allow(Addrinfo).to receive(:getaddrinfo).with('localhost', nil, nil, :STREAM) do
				addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
			end

			grades = server host: '::1' do
				analyze 'localhost', 5000
			end

			expect_grade_error grades, 'localhost', '127.0.0.1', 5000,
							   'Connection refused - connect(2) for 127.0.0.1:5000'
			expect_grade grades, 'localhost', '::1', 5000, :ipv6
		end

		it 'return error if TCP timeout' do
			stub_const 'CryptCheck::Tls::Server::TCP_TIMEOUT', 1
			addresses = %w(127.0.0.1 ::1)
			allow(Addrinfo).to receive(:getaddrinfo).with('localhost', nil, nil, :STREAM) do
				addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
			end
			original = IO.method :select
			allow(IO).to receive(:select) do |*args, &block|
				socket = [args[0]&.first, args[1]&.first].compact.first
				next nil if socket.is_a?(Socket) && (socket.local_address.afamily == Socket::AF_INET)
				original.call *args, &block
			end

			grades = server host: '::' do
				analyze 'localhost', 5000
			end

			expect_grade_error grades, 'localhost', '127.0.0.1', 5000,
							   'Timeout when connect to 127.0.0.1:5000 (max 1 second)'
			expect_grade grades, 'localhost', '::1', 5000, :ipv6
		end

		it 'return error if TLS timeout' do
			stub_const 'CryptCheck::Tls::Server::SSL_TIMEOUT', 1
			addresses = %w(127.0.0.1 ::1)
			allow(Addrinfo).to receive(:getaddrinfo).with('localhost', nil, nil, :STREAM) do
				addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
			end
			original = IO.method :select
			allow(IO).to receive(:select) do |*args, &block|
				socket = [args[0]&.first, args[1]&.first].compact.first
				next nil if socket.is_a?(OpenSSL::SSL::SSLSocket) && (socket.io.local_address.afamily == Socket::AF_INET)
				original.call *args, &block
			end

			grades = server host: '::' do
				analyze 'localhost', 5000
			end

			expect_grade_error grades, 'localhost', '127.0.0.1', 5000,
							   'Timeout when TLS connect to 127.0.0.1:5000 (max 1 second)'
			expect_grade grades, 'localhost', '::1', 5000, :ipv6
		end

		it 'return error if plain server' do
			stub_const 'CryptCheck::Tls::Server::SSL_TIMEOUT', 1
			addresses = %w(127.0.0.1 ::1)
			allow(Addrinfo).to receive(:getaddrinfo).with('localhost', nil, nil, :STREAM) do
				addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
			end

			grades = plain_server host: '127.0.0.1' do
				server host: '::1' do
					analyze 'localhost', 5000
				end
			end

			expect_grade_error grades, 'localhost', '127.0.0.1', 5000,
							   'TLS seems not supported on this server'
			expect_grade grades, 'localhost', '::1', 5000, :ipv6
		end
	end
end
