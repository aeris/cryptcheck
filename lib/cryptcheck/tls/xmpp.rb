require 'erb'
require 'logging'
require 'parallel'

module CryptCheck
	module Tls
		module Xmpp
			MAX_ANALYSIS_DURATION = 600
			PARALLEL_ANALYSIS = 10
			Logger = ::Logging.logger[Xmpp]

			def self.grade(hostname, type=:s2s)
				timeout MAX_ANALYSIS_DURATION do
					Grade.new Server.new hostname, type
				end
			rescue ::Exception => e
				Logger.error { "Error during #{hostname}:#{type} analysis : #{e}" }
				TlsNotSupportedGrade.new TlsNotSupportedServer.new hostname, type
			end

			def self.analyze(hosts, output)
				servers = []
				semaphore = ::Mutex.new
				::Parallel.each hosts, progress: 'Analysing', in_threads: PARALLEL_ANALYSIS, finish: lambda { |item, _, _| puts item } do |host|
										 result = grade host.strip
										 semaphore.synchronize { servers << result }
									 end
				servers.sort! do |a, b|
					cmp = score(a) <=> score(b)
					if cmp == 0
						cmp = b.score <=> a.score
						if cmp == 0
							cmp = a.server.hostname <=> b.server.hostname
						end
					end
					cmp
				end

				::File.write output, ::ERB.new(::File.read('output/xmpp.erb')).result(binding)
			end

			def self.analyze_from_file(file, output)
				hosts = ::YAML.load_file file
				self.analyze hosts, output
			end

			private
			SCORES = %w(A+ A A- B C D E F T M X)

			def self.score(a)
				SCORES.index a.grade
			end
		end
	end
end
