require 'amazing_print'
require 'timeout'

module CryptCheck
  class Host
    MAX_ANALYSIS_DURATION = ENV.fetch('MAX_ANALYSIS_DURATION', '600').to_i

    attr_reader :servers, :error

    def initialize(hostname, port)
      @hostname, @port = hostname, port

      first    = true
      @servers = resolve.collect do |args|
        _, ip = args
        first ? (first = false) : Logger.info { '' }
        result = begin
                   server = ::Timeout.timeout MAX_ANALYSIS_DURATION do
                     server(*args)
                   end
                   Logger.info ''
                   Logger.info { "Grade : #{server.grade.to_s.colorize server.grade_status}" }
                   Logger.info { server.states.ai }
                   server
                 rescue => e
                   Logger.error { e }
                   raise if ENV['DEV_MODE']
                   e
                 end
        [[@hostname, ip, @port], result]
      end.to_h
    rescue => e
      Logger.error { e }
      @error = e
      raise if CryptCheck.dev?
    end

    def key
      { hostname: @hostname, port: @port }
    end

    def to_h
      if @error
        target = [self.key.merge(error: @error.to_s)]
      else
        target = @servers.collect do |host, server|
          hostname, ip, port = host
          host               = {
            hostname: hostname,
            ip:       ip,
            port:     port
          }
          case server
          when Server
            host[:handshakes] = server.to_h
            host[:states]     = server.states
            host[:grade]      = server.grade
          else
            host[:error] = server.to_s
          end
          host
        end
      end
      target
    end

    private

    def resolve
      begin
        begin
          ip = IPAddr.new @hostname
          return [[nil, ip.to_s, ip.family, @port]]
        rescue IPAddr::InvalidAddressError
        end
        ::Addrinfo.getaddrinfo(@hostname, nil, nil, :STREAM)
          .collect { |a| [@hostname, a.ip_address, a.afamily, @port] }
      end.reject do |_, _, family, *_|
        (ENV['DISABLE_IPv6'] && family == Socket::AF_INET6) ||
          (ENV['DISABLE_IPv4'] && family == Socket::AF_INET)
      end
    end
  end
end
