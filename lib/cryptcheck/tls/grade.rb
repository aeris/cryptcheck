module CryptCheck
	module Tls
		class Grade
			attr_reader :server, :grade, :states

			def initialize(server)
				@server = server
				@checks = checks
				@states = calculate_states
				@grade = calculate_grade
			end

			def display
				color = case @grade
							when 'A', 'A+'
								:best
							when 'B', 'B+'
								:perfect
							when 'C', 'C+'
								nil
							when 'E'
								:warning
							when 'F'
								:error
							when 'G'
								:critical
							when 'M', 'T'
								:unknown
						end

				Logger.info { "Grade : #{self.grade.colorize color }" }
				Logger.info { '' }
				[
						['Critical', :critical],
						['Error', :error],
						['Warning', :warning],
						['Good', :good],
						['Perfect', :perfect],
						['Best', :best],
				].each do |text, color|
					states = @states[color]
					Logger.info { "#{text} : #{states.collect { |s| s.to_s.colorize color }.join ' '}" } unless states.empty?
				end
			end

			private
			def calculate_grade
				case
					when !@states[:critical].empty?
						return 'G'
					when !@states[:error].empty?
						return 'F'
					when !@states[:warning].empty?
						return 'E'
				end

				goods = @checks.select { |c| c.last == :good }.collect &:first
				unless goods.empty?
					return 'D' if @states[:good].empty?
					return 'C' if @states[:good] != goods
				end

				perfects = @checks.select { |c| c.last == :perfect }.collect &:first
				unless perfects.empty?
					return 'C+' if @states[:perfect].empty?
					return 'B' if @states[:perfect] != perfects
				end

				bests = @checks.select { |c| c.last == :best }.collect &:first
				unless bests.empty?
					return 'B+' if @states[:best].empty?
					return 'A' if @states[:best] != bests
				end

				'A+'
			end

			CHECKS = [
					# Keys
					[:dss_sign, Proc.new { |s| s.dss_sig? }, :critical],
					[:weak_key, Proc.new { |s| %i(critical error warning) & [s.key.status] } ],

					# DH
					[:weak_dh, Proc.new { |s| (%i(critical error warning) & s.dh.collect(&:status).uniq).first } ],

					# Certificates
					[:md2_sign, Proc.new { |s| s.md2_sig? }, :critical],
					[:mdc2_sign, Proc.new { |s| s.mdc2_sig? }, :critical],
					[:md4_sign, Proc.new { |s| s.md4_sig? }, :critical],
					[:md5_sign, Proc.new { |s| s.md5_sig? }, :critical],
					[:sha_sign, Proc.new { |s| s.sha_sig? }, :critical],

					[:sha1_sign, Proc.new { |s| s.sha1_sig? }, :warning],

					# Protocols
					[:ssl, Proc.new { |s| s.ssl? }, :critical],
					[:tls12, Proc.new { |s| s.tlsv1_2? }, :good],
					[:tls12_only, Proc.new { |s| s.tlsv1_2_only? }, :perfect],

					# Ciphers
					[:dss, Proc.new { |s| s.dss? }, :critical],
					[:anonymous, Proc.new { |s| s.anonymous? }, :critical],
					[:null, Proc.new { |s| s.null? }, :critical],
					[:export, Proc.new { |s| s.export? }, :critical],
					[:des, Proc.new { |s| s.des? }, :critical],
					[:md5, Proc.new { |s| s.md5? }, :critical],

					[:rc4, Proc.new { |s| s.rc4? }, :error],
					[:sweet32, Proc.new { |s| s.sweet32? }, :error],

					[:no_pfs, Proc.new { |s| not s.pfs_only? }, :warning],
					[:pfs, Proc.new { |s| s.pfs? }, :good],
					[:pfs_only, Proc.new { |s| s.pfs_only? }, :perfect],
					[:ecdhe, Proc.new { |s| s.ecdhe? }, :good],
					[:ecdhe_only, Proc.new { |s| s.ecdhe_only? }, :perfect],

					[:aead, Proc.new { |s| s.aead? }, :good],
					#[:aead_only, Proc.new { |s| s.aead_only? }, :best],
			]

			def checks
				checks = CHECKS
				unless @server.fallback_scsv? == nil
					checks += [
						[:no_fallback_scsv, Proc.new { |s| not s.fallback_scsv? }, :error],
						[:fallback_scsv, Proc.new { |s| s.fallback_scsv? }, :good]
					]
				end
				checks
			end

			def calculate_states
				states = { critical: [], error: [], warning: [], good: [], perfect: [], best: [] }
				@checks.each do |name, check, status|
					result = check.call @server
					if result
						state = states[status ? status : result]
						state << name if state
					end
				end
				states
			end
		end
	end
end
