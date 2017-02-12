module CryptCheck
	module Tls
		class Grade
			attr_reader :server, :grade

			def initialize(server)
				@server = server
				@checks = checks
				@states = @server.states
				Logger.info { '' }
				Logger.ap :checks, @checks
				Logger.ap :states, @states
				@grade = calculate_grade

				color = case @grade
							when 'A', 'A+'
								:best
							when 'B', 'B+'
								:perfect
							when 'C', 'C+'
								:good
							when 'E'
								:warning
							when 'F'
								:error
							when 'G'
								:critical
							when 'T', 'V'
								:unknown
						end

				Logger.info { "Grade : #{self.grade.colorize color }" }
			end

			private
			CHECKS = {
					best:     %i(

							  ),
					perfect:  %i(
						tlsv1_2_only
						pfs_only
						ecdhe_only
					),
					good:     %i(
						tlsv1_2
						pfs
						ecdhe
						aead
					),
					warning:  %i(
						weak_key
						weak_dh
						dhe
					),
					error:    %i(
						weak_key
						weak_dh
					),
					critical: %i(
						mdc2_sign md2_sign md4_sign md5_sign sha_sign sha1_sign
						weak_key
						weak_dh
						sslv2 sslv3
					),
			}.freeze

			def checks
				CHECKS
			end

			def calculate_grade
				return 'V' unless @server.valid?
				return 'T' unless @server.trusted?

				case
					when !@states[:critical].empty?
						return 'G'
					when !@states[:error].empty?
						return 'F'
					when !@states[:warning].empty?
						return 'E'
				end

				[[:good, 'D', 'C'],
				 [:perfect, 'C', 'B'],
				 [:best, 'B', 'A']].each do |type, score1, score2|
					expected = @checks[type]
					unless expected.empty?
						available = @states[type]
						return score1 if available.empty?
						missed = expected - available
						unless missed.empty?
							Logger.info { "Missing #{type} : #{missed}" }
							return score2
						end

						# I'm not error prone. The code yes.
						additional = available - expected
						unless additional.empty?
							Logger.fatal { "Developper missed #{type} : #{additional}".colorize :critical }
							exit -1
						end
					end
				end

				'A+'
			end
		end
	end
end
