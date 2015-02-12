require 'erb'
require 'logging'
require 'parallel'

module CryptCheck
	module Tls
		module Https
			MAX_ANALYSIS_DURATION = 600
			PARALLEL_ANALYSIS = 10
			@@log = ::Logging.logger[Https]

			def self.grade(hostname, port=443)
				timeout MAX_ANALYSIS_DURATION do
					Grade.new Server.new hostname, port
				end
			rescue ::Exception => e
				@@log.error { "Error during #{hostname}:#{port} analysis : #{e}" }
				TlsNotSupportedGrade.new TlsNotSupportedServer.new hostname, port
			end

			def self.analyze(hosts, output, groups = nil)
				results = {}
				semaphore = ::Mutex.new
				::Parallel.each hosts, progress: 'Analysing', in_threads: PARALLEL_ANALYSIS, finish: lambda { |item, _, _| puts item[1] } do |description, host|
					result = grade host.strip
					semaphore.synchronize do
						if results.include? description
							results[description] << result
						else
							results[description] = [result]
						end
					end
				end

				results = ::Hash[groups.collect { |g| [g, results[g]] }] if groups

				results.each do |d, _|
					results[d].sort! do |a, b|
						cmp = score(a) <=> score(b)
						if cmp == 0
							cmp = b.score <=> a.score
							if cmp == 0
								cmp = a.server.hostname <=> b.server.hostname
							end
						end
						cmp
					end
				end

				::File.write output, ::ERB.new(::File.read('output/https.erb')).result(binding)
			end

			def self.analyze_from_file(file, output)
				config = ::YAML.load_file file
				hosts = []
				groups = []
				config.each do |c|
					d, hs = c['description'], c['hostnames']
					groups << d
					hs.each { |host| hosts << [d, host] }
				end
				self.analyze hosts, output, groups
			end

			private
			SCORES = %w(A+ A A- B C D E F T M X)

			def self.score(a)
				SCORES.index a.grade
			end
		end
	end
end
