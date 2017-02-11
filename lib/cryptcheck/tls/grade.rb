module CryptCheck
	module Tls
		class Grade
			attr_reader :server, :grade, :status

			def initialize(server)
				@server = server
				@status = @server.status
				@checks = checks
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
				State.each do |color|
					states = @status[color]
					Logger.info { "#{color.to_s.capitalize} : #{states.collect { |s| s.to_s.colorize color }.join ' '}" } unless states.empty?
				end
			end

			private
			CHECKS = {
					critical: %i(
						mdc2_sign md2_sign md4_sign md5_sign sha_sign sha1_sign
						weak_key
						weak_dh
						sslv2 sslv3
					),
					error:    %i(
						weak_key
						weak_dh
					),
					warning:  %i(
						weak_key
						weak_dh
						dhe
					),
					good:     %i(
						tls12
					),
					perfect:  %i(
						tls12_only
					),
					best:     %i(

							  )
			}.freeze

			def checks

			end

			def calculate_grade
				case
					when !@status[:critical].empty?
						return 'G'
					when !@status[:error].empty?
						return 'F'
					when !@status[:warning].empty?
						return 'E'
				end

				goods = @checks.select { |c| c.last == :good }.collect &:first
				unless goods.empty?
					return 'D' if @status[:good].empty?
					return 'C' if @status[:good] != goods
				end

				perfects = @checks.select { |c| c.last == :perfect }.collect &:first
				unless perfects.empty?
					return 'C+' if @status[:perfect].empty?
					return 'B' if @status[:perfect] != perfects
				end

				bests = @checks.select { |c| c.last == :best }.collect &:first
				unless bests.empty?
					return 'B+' if @status[:best].empty?
					return 'A' if @status[:best] != bests
				end

				'A+'
			end
		end
	end
end
