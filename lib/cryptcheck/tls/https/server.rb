require 'httparty'

module CryptCheck
	module Tls
		module Https
			class Server < Tls::TcpServer
				attr_reader :hsts

				def initialize(hostname, port=443)
					super
					fetch_hsts
				end

				def fetch_hsts
					port = @port == 443 ? '' : ":#{@port}"

					response = nil
					EXISTING_METHODS.each do |method|
						begin
							next unless SUPPORTED_METHODS.include? method
							@log.debug { "Check HSTS with #{method}" }
							response = ::HTTParty.head "https://#{@hostname}#{port}/", { follow_redirects: false, verify: false, ssl_version: method, timeout: SSL_TIMEOUT }
							break
						rescue Exception => e
							@log.debug { "#{method} not supported : #{e}" }
						end
					end

					if response and header = response.headers['strict-transport-security']
						name, value = header.split '='
						if name == 'max-age'
							@hsts = value.to_i
							@log.info { "HSTS : #{@hsts}" }
							return
						end
					end

					@log.info { 'No HSTS' }
					@hsts = nil
				end

				def hsts?
					!@hsts.nil?
				end

				def hsts_long?
					hsts? and @hsts >= 6*30*24*60*60 # ~6month
				end
			end
		end
	end
end
