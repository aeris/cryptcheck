require 'awesome_print'
AwesomePrint.force_colors = true
require 'timeout'

module CryptCheck
	module Tls
		class AnalysisFailure
			attr_reader :error

			def initialize(error)
				@error = error
			end

			def to_s
				@error.to_s
			end
		end

		class TooLongAnalysis < AnalysisFailure
			def initialize
				super "Too long analysis (max #{Host::MAX_ANALYSIS_DURATION.humanize})"
			end
		end

		class Host
			MAX_ANALYSIS_DURATION = 600

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
					rescue Engine::TLSException, Engine::ConnectionError, Engine::Timeout => e
						# Logger.error { e.backtrace }
						Logger.error { e }
						AnalysisFailure.new e
					rescue ::Timeout::Error
						# Logger.error { e.backtrace }
						Logger.error { e }
						TooLongAnalysis.new
					end
					[[@hostname, ip, @port], result]
				end.to_h
			rescue => e
				# Logger.error { e.backtrace }
				Logger.error { e }
				@error = e
			end

			def key
				{ hostname: @hostname, port: @port }
			end

			def to_h
				if @error
					target = { error: @error }
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
								host[:grade]     = server.grade
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
					ip = IPAddr.new @hostname
					return [[nil, ip.to_s, ip.family, @port]]
				rescue IPAddr::InvalidAddressError
				end
				::Addrinfo.getaddrinfo(@hostname, nil, nil, :STREAM)
						.collect { |a| [@hostname, a.ip_address, a.afamily, @port] }
			end

			def server(*args)
				TcpServer.new *args
			end
		end
	end
end
