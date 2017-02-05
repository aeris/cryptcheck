require 'httparty'

module CryptCheck
	module Tls
		module Https
			class Server < Tls::TcpServer
				attr_reader :hsts

				def initialize(hostname, family, ip, port=443)
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
														   timeout:          SSL_TIMEOUT,
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
					rescue
					end

					Logger.info { 'No HSTS'.colorize :warning }
					@hsts = nil
				end

				def hsts?
					!@hsts.nil?
				end

				LONG_HSTS = 6*30*24*60*60

				def hsts_long?
					hsts? and @hsts >= LONG_HSTS
				end

				def checks
					super + [
							[:hsts, -> (s) { s.hsts? }, :good],
							[:hsts_long, -> (s) { s.hsts_long? }, :perfect],
							#[:must_staple, -> (s) { s.must_staple? }, :best],
					]
				end
			end
		end
	end
end
