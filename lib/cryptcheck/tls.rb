require 'erb'
require 'parallel'

module CryptCheck
	module Tls
		MAX_ANALYSIS_DURATION = 600
		PARALLEL_ANALYSIS     = 10

		def self.grade(hostname, port, server_class:, grade_class:)
			timeout MAX_ANALYSIS_DURATION do
				grade_class.new server_class.new hostname, port
			end
		rescue ::Exception => e
			Logger.error { "Error during #{hostname}:#{port} analysis : #{e}" }
			TlsNotSupportedGrade.new TlsNotSupportedServer.new hostname, port
		end

		def self.analyze(hosts, template, output, groups = nil, port:, server_class:, grade_class:)
			results   = {}
			semaphore = ::Mutex.new
			::Parallel.each hosts, progress: 'Analysing', in_threads: PARALLEL_ANALYSIS, finish: lambda { |item, _, _| puts item[1] } do |description, host|
									 result = grade host.strip, port, server_class: server_class, grade_class: grade_class
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

			::File.write output, ::ERB.new(::File.read(template)).result(binding)
		end

		def self.analyze_from_file(file, template, output, port:, server_class:, grade_class:)
			config = ::YAML.load_file file
			hosts  = []
			groups = []
			config.each do |c|
				d, hs = c['description'], c['hostnames']
				groups << d
				hs.each { |host| hosts << [d, host] }
			end
			self.analyze hosts, template, output, groups, port: port, server_class: server_class, grade_class: grade_class
		end

		def self.colorize(cipher)
			colors = case
						 when /^SSL/ =~ cipher then { color: :white, background: :red }
						 when :TLSv1_2 == cipher then { color: :green }
					 end
			cipher.to_s.colorize colors
		end

		def self.key_to_s(key)
			size       = key.rsa_equivalent_size
			type_color = case key.type
							 when :ecc then { color: :green }
							 when :dsa then { color: :yellow }
						 end
			size_color = case size
							 when 0...1024 then { color: :white, background: :red }
							 when 1024...2048 then { color: :yellow }
							 when 4096...::Float::INFINITY then { color: :green }
						 end
			"#{key.type.to_s.upcase.colorize type_color} #{key.size.to_s.colorize size_color} bits"
		end

		private
		SCORES = %w(A+ A A- B C D E F T M X)

		def self.score(a)
			SCORES.index a.grade
		end
	end
end
