module CryptCheck
	module Tls
		class Grade
			attr_reader :server, :grade

			def initialize(server)
				@server = server
				@states = @server.states
				@checks = @server.performed_checks
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
					end
				end

				'A+'
			end
		end
	end
end
