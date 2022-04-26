require 'httparty'

module CryptCheck
  module Tls
    module Https
      class Server < Tls::Server
        attr_reader :hsts

        def initialize(hostname, ip, family, port = 443)
          super
          fetch_hsts
        end

        def fetch_hsts
          port = @port == 443 ? '' : ":#{@port}"

          begin
            response = ::HTTParty.head "https://#{@hostname}#{port}/",
                                       {
                                         follow_redirects: false,
                                         verify:           false,
                                         timeout:          TLS_TIMEOUT,
                                         ssl_version:      @supported_methods.first.to_sym,
                                         ciphers:          Cipher::ALL
                                       }
            if header = response.headers['strict-transport-security']
              name, value = header.split '='
              if name == 'max-age'
                @hsts = value.to_i
                Logger.info { 'HSTS : ' + @hsts.to_s.colorize(hsts_long? ? :good : nil) }
                return
              end
            end
          rescue Exception => e
            Logger.debug { e }
          end

          Logger.info { 'No HSTS'.colorize :warning }
          @hsts = nil
        end

        def hsts?
          !@hsts.nil?
        end

        LONG_HSTS = 6 * 30 * 24 * 60 * 60

        def hsts_long?
          hsts? and @hsts >= LONG_HSTS
        end

        def to_h
          super.merge({ hsts: @hsts })
        end

        protected

        def available_checks
          super + [
            [:hsts, %i(warning good great), -> (s) { s.hsts_long? ? :great : s.hsts? ? :good : :warning }],
          #[:must_staple, :best, -> (s) { s.must_staple? }],
          ]
        end
      end
    end
  end
end
