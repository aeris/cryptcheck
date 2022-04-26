module CryptCheck::Tls
  describe Host do
    def host(*args, **kargs)
      tls_serv(*args, **kargs) { |h, p| Host.new h, p }
    end

    def servers(*args, **kargs)
      host(*args, **kargs).servers
    end

    def error(*args, **kargs)
      host(*args, **kargs).error
    end

    host = Helpers::DEFAULT_HOST
    ipv4 = Helpers::DEFAULT_IPv4
    ipv6 = Helpers::DEFAULT_IPv6
    port = Helpers::DEFAULT_PORT

    it 'return 1 grade with IPv4' do
      servers = servers(ips: [ipv4])
      expect(servers.size).to be 1
      expect_grade servers, host, ipv4, port, :ipv4
    end

    it 'return 1 grade with IPv6' do
      servers = servers(ips: [ipv6])
      expect(servers.size).to be 1
      expect_grade servers, host, ipv6, port, :ipv6
    end

    it 'return 2 grades with hostname (IPv4 & IPv6)' do
      servers = servers()
      expect(servers.size).to be 2
      expect_grade servers, host, ipv4, port, :ipv4
      expect_grade servers, host, ipv6, port, :ipv6
    end

    it 'return error if DNS resolution problem' do
      allow(Addrinfo).to receive(:getaddrinfo).with(host, nil, nil, :STREAM)
                                              .and_raise SocketError, 'getaddrinfo: Name or service not known'
      error = error()
      expect_error error, ::SocketError, 'getaddrinfo: Name or service not known'
    end

    it 'return error if analysis too long' do
      stub_const 'CryptCheck::Host::MAX_ANALYSIS_DURATION', 1
      allow_any_instance_of(Host).to receive(:server) { sleep 2 }

      servers = servers()
      expect_grade_error servers, host, ipv4, port,
                         'Too long analysis (max 1 second)'
    end

    # it 'return error if unable to connect' do
    #   servers = servers(ips: [ipv6], fake_ips: [ipv6, ipv4])
    #   expect_grade servers, host, ipv6, port, :ipv6
    #   expect_grade_error servers, host, ipv4, port,
    #                      'Connection refused - connect(2) for 127.0.0.1:15000'
    # end

    # it 'return error if TCP timeout' do
    #   stub_const 'CryptCheck::Tls::Engine::TCP_TIMEOUT', 1
    #   original = IO.method :select
    #   allow(IO).to receive(:select) do |*args, &block|
    #     socket = [args[0]&.first, args[1]&.first].compact.first
    #     next nil if socket.is_a?(Socket) && (socket.local_address.afamily == Socket::AF_INET)
    #     original.call *args, &block
    #   end
    #
    #   servers = servers()
    #   expect_grade_error servers, host, ipv4, port,
    #                      'Timeout when connecting to 127.0.0.1:15000 (max 1 second)'
    #   expect_grade servers, host, ipv6, port, :ipv6
    # end
    #
    # it 'return error if TLS timeout' do
    #   stub_const 'CryptCheck::Tls::Engine::TLS_TIMEOUT', 1
    #   original = IO.method :select
    #   allow(IO).to receive(:select) do |*args, &block|
    #     socket = [args[0]&.first, args[1]&.first].compact.first
    #     next nil if socket.is_a?(OpenSSL::SSL::SSLSocket) && (socket.io.local_address.afamily == Socket::AF_INET)
    #     original.call *args, &block
    #   end
    #
    #   servers = servers()
    #   expect_grade_error servers, host, ipv4, port,
    #                      'Timeout when TLS connecting to 127.0.0.1:15000 (max 1 second)'
    #   expect_grade servers, host, ipv6, port, :ipv6
    # end

    it 'return error if plain server' do
      servers = plain_serv() { |h, p| Host.new(h, p).servers }
      expect_grade_error servers, host, ipv4, port, 'TLS seems not supported on this server'
      expect_grade_error servers, host, ipv6, port, 'TLS seems not supported on this server'
    end
  end
end
