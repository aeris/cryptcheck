module CryptCheck
	module Tls
		class Grade
			attr_reader :server, :score, :grade, :error, :danger, :warning, :success

			def initialize(server)
				@server = server
				calculate_states
				calculate_grade
			end

			def display
				color = case self.grade
							when 'A+' then :blue
							when 'A' then :green
							when 'B', 'C' then :yellow
							when 'E', 'F' then :red
							when 'M', 'T' then { color: :white, background: :red }
						end

				Logger.info { "Grade : #{self.grade.colorize color }" }
				Logger.info { '' }
				Logger.info { "Errors : #{self.error.join(' ').colorize :red }" } unless self.error.empty?
				Logger.info { "Warnings : #{self.warning.join(' ').colorize :yellow }" } unless self.warning.empty?
				Logger.info { "Best practices : #{self.success.join(' ').colorize :green }" } unless self.success.empty?
			end

			private
			def calculate_grade
				@grade = case @score
							 when 0...20 then 'F'
							 when 20...35 then 'E'
							 when 35...50 then 'D'
							 when 50...65 then 'C'
							 when 65...80 then 'B'
							 else 'A'
						 end

				@grade = [@grade, 'B'].max if !@server.tlsv1_2? or %i(error warning).include? @server.key.status
				@grade = [@grade, 'F'].max unless @error.empty?
				@grade = [@grade, 'F'].max unless @error.empty?

				@grade = 'M' unless @server.cert_valid
				@grade = 'T' unless @server.cert_trusted

				@grade = 'A+' if @grade == 'A' and @error.empty? and @warning.empty? and (all_success & @success) == all_success
			end

			def calculate_states
				ok = Proc.new { |n| @server.send "#{n}?" }
				state = {
						success: all_success.select { |n| ok.call n },
						warning: all_warning.select { |n| ok.call n },
						danger:  all_danger.select { |n| ok.call n },
						error:   all_error.select { |n| ok.call n }
				}
				@success, @warning, @danger, @error = state[:success], state[:warning], state[:danger], state[:error]
			end

			ALL_ERROR = %i(md5_sig md5 anonymous dss null export des des3 rc4)
			def all_error
				ALL_ERROR
			end

			ALL_DANGER = %i()
			def all_danger
				ALL_DANGER
			end

			ALL_WARNING = %i(sha1_sig)
			def all_warning
				ALL_WARNING
			end

			ALL_SUCCESS = %i(pfs_only)
			def all_success
				ALL_SUCCESS
			end
		end
	end
end
