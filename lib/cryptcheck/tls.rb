require 'erb'
require 'logging'
require 'parallel'

module CryptCheck
	module Tls
		MAX_ANALYSIS_DURATION = 600
		PARALLEL_ANALYSIS     = 10

		TYPES = {
				md5:       %w(MD5),
				sha1:      %w(SHA),

				psk:       %w(PSK),
				srp:       %w(SRP),
				anonymous: %w(ADH AECDH),

				dss:       %w(DSS),

				null:      %w(NULL),
				export:    %w(EXP),
				des:       %w(DES-CBC),
				rc4:       %w(RC4),
				des3:      %w(3DES DES-CBC3),

				pfs:       %w(DHE EDH ECDHE ECDH)
		}

		TYPES.each do |name, ciphers|
			class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
				def self.#{name}?(cipher)
					#{ciphers}.any? { |c| /(^|-)#\{c\}(-|$)/ =~ cipher }
				end
			RUBY_EVAL
		end

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
						 when /^SSL/ =~ cipher,
								 dss?(cipher),
								 anonymous?(cipher),
								 null?(cipher),
								 export?(cipher),
								 md5?(cipher),
								 des?(cipher),
								 rc4?(cipher)
							 { color: :white, background: :red }
						 when des3?(cipher)
							 { color: :yellow }
						 when :TLSv1_2 == cipher,
								 pfs?(cipher)
							 { color: :green }
					 end
			cipher.to_s.colorize colors
		end

		private
		SCORES = %w(A+ A A- B C D E F T M X)

		def self.score(a)
			SCORES.index a.grade
		end
	end
end
