describe CryptCheck::Tls::Host do
	def host(*args, **kargs)
		do_in_serv *args, **kargs do |host, port|
			CryptCheck::Tls::Host.new host, port
		end
	end

	def servers(*args, **kargs)
		host(*args, **kargs).servers
	end

	def error(*args, **kargs)
		host(*args, **kargs).error
	end

	it 'return 1 grade with IPv4' do
		servers = servers()
		expect(servers.size).to be 1
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv4, Helpers::DEFAULT_PORT, :ipv4
	end

	it 'return 1 grade with IPv6' do
		addresses = [Helpers::DEFAULT_IPv6]
		allow(Addrinfo).to receive(:getaddrinfo).with(Helpers::DEFAULT_HOST, nil, nil, :STREAM) do
			addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
		end

		servers = servers(host: Helpers::DEFAULT_IPv6)
		expect(servers.size).to be 1
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv6, Helpers::DEFAULT_PORT, :ipv6
	end

	it 'return 2 grades with hostname (IPv4 & IPv6)' do
		addresses = [Helpers::DEFAULT_IPv4, Helpers::DEFAULT_IPv6]
		allow(Addrinfo).to receive(:getaddrinfo).with(Helpers::DEFAULT_HOST, nil, nil, :STREAM) do
			addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
		end

		servers = servers(host: '::')
		expect(servers.size).to be 2
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv4, Helpers::DEFAULT_PORT, :ipv4
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv6, Helpers::DEFAULT_PORT, :ipv6
	end

	it 'return error if DNS resolution problem' do
		allow(Addrinfo).to receive(:getaddrinfo).with(Helpers::DEFAULT_HOST, nil, nil, :STREAM)
								   .and_raise SocketError, 'getaddrinfo: Name or service not known'

		error = error()
		expect_error error, ::SocketError, 'getaddrinfo: Name or service not known'
	end

	it 'return error if analysis too long' do
		stub_const 'CryptCheck::Tls::Host::MAX_ANALYSIS_DURATION', 1
		allow_any_instance_of(CryptCheck::Tls::Host).to receive(:server) { sleep 2 }

		servers = servers()
		expect_grade_error servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv4, Helpers::DEFAULT_PORT,
						   'Too long analysis (max 1 second)'
	end

	it 'return error if unable to connect' do
		addresses = [Helpers::DEFAULT_IPv4, Helpers::DEFAULT_IPv6]
		allow(Addrinfo).to receive(:getaddrinfo).with(Helpers::DEFAULT_HOST, nil, nil, :STREAM) do
			addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
		end

		servers = servers(host: Helpers::DEFAULT_IPv6)
		expect_grade_error servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv4, Helpers::DEFAULT_PORT,
						   'Connection refused - connect(2) for 127.0.0.1:15000'
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv6, Helpers::DEFAULT_PORT, :ipv6
	end

	it 'return error if TCP timeout' do
		stub_const 'CryptCheck::Tls::Engine::TCP_TIMEOUT', 1
		addresses = [Helpers::DEFAULT_IPv4, Helpers::DEFAULT_IPv6]
		allow(Addrinfo).to receive(:getaddrinfo).with(Helpers::DEFAULT_HOST, nil, nil, :STREAM) do
			addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
		end

		original = IO.method :select
		allow(IO).to receive(:select) do |*args, &block|
			socket = [args[0]&.first, args[1]&.first].compact.first
			next nil if socket.is_a?(Socket) && (socket.local_address.afamily == Socket::AF_INET)
			original.call *args, &block
		end

		servers = servers(host: '::')
		expect_grade_error servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv4, Helpers::DEFAULT_PORT,
						   'Timeout when connecting to 127.0.0.1:15000 (max 1 second)'
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv6, Helpers::DEFAULT_PORT, :ipv6
	end

	it 'return error if TLS timeout' do
		stub_const 'CryptCheck::Tls::Engine::TLS_TIMEOUT', 1
		addresses = [Helpers::DEFAULT_IPv4, Helpers::DEFAULT_IPv6]
		allow(Addrinfo).to receive(:getaddrinfo).with(Helpers::DEFAULT_HOST, nil, nil, :STREAM) do
			addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
		end

		original = IO.method :select
		allow(IO).to receive(:select) do |*args, &block|
			socket = [args[0]&.first, args[1]&.first].compact.first
			next nil if socket.is_a?(OpenSSL::SSL::SSLSocket) && (socket.io.local_address.afamily == Socket::AF_INET)
			original.call *args, &block
		end

		servers = servers(host: '::')
		expect_grade_error servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv4, Helpers::DEFAULT_PORT,
						   'Timeout when TLS connecting to 127.0.0.1:15000 (max 1 second)'
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv6, Helpers::DEFAULT_PORT, :ipv6
	end

	it 'return error if plain server' do
		stub_const 'CryptCheck::Tls::ENGINE::TLS_TIMEOUT', 1
		addresses = [Helpers::DEFAULT_IPv4, Helpers::DEFAULT_IPv6]
		allow(Addrinfo).to receive(:getaddrinfo).with(Helpers::DEFAULT_HOST, nil, nil, :STREAM) do
			addresses.collect { |a| Addrinfo.new Socket.sockaddr_in(nil, a) }
		end

		servers = plain_serv Helpers::DEFAULT_IPv4 do
			servers(host: Helpers::DEFAULT_IPv6)
		end
		expect_grade_error servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv4, Helpers::DEFAULT_PORT,
						   'TLS seems not supported on this server'
		expect_grade servers, Helpers::DEFAULT_HOST, Helpers::DEFAULT_IPv6, Helpers::DEFAULT_PORT, :ipv6
	end

end
