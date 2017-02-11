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

			attr_reader :servers

			def initialize
				first    = true
				@servers = resolve.collect do |args|
					first ? (first = false) : Logger.info { '' }
					result = begin
						server = ::Timeout.timeout MAX_ANALYSIS_DURATION do
							server(*args)
						end
						grade(server)
					rescue Engine::TLSException => e
						AnalysisFailure.new e
					rescue ::Timeout::Error
						TooLongAnalysis.new
					end
					[args, result]
				end.to_h
			end
		end
	end
end
