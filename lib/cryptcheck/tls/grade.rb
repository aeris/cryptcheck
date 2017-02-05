module CryptCheck
	module Tls
		class Grade
			attr_reader :server, :grade, :states

			def initialize(server)
				@server = server
				@checks = checks
				@states = calculate_states
				@grade  = calculate_grade
			end

			def display
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
							when 'M', 'T'
								:unknown
						end

				Logger.info { "Grade : #{self.grade.colorize color }" }
				Logger.info { '' }
				Status.each do |color|
					states = @states[color]
					Logger.info { "#{color.to_s.capitalize} : #{states.collect { |s| s.to_s.colorize color }.join ' '}" } unless states.empty?
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
		end
	end
end
