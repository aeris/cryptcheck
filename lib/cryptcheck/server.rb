module CryptCheck
  class Server
  end

  class TcpServer < Server
    private

    def sock_type
      ::Socket::SOCK_STREAM
    end
  end

  class UdpServer < Server
    private

    def sock_type
      ::Socket::SOCK_DGRAM
    end
  end
end
