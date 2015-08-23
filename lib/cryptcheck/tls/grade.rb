module CryptCheck
	module Tls
		class TlsNotSupportedGrade
			attr_reader :server, :score, :grade

			def initialize(server)
				@server, @score, @grade = server, -1, 'X'
			end
		end

		class Grade
			attr_reader :server, :protocol_score, :key_exchange_score, :cipher_strengths_score, :score, :grade, :error, :warning, :success

			def initialize(server)
				@server = server
				calculate_protocol_score
				calculate_key_exchange_score
				calculate_cipher_strengths_score
				@score = @protocol_score*0.3 + @key_exchange_score*0.3 + @cipher_strengths_score*0.4
				calculate_error
				calculate_warning
				calculate_success
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
				Logger.info { "Protocole : #{self.protocol_score} / 100" }
				Logger.info { "Key exchange : #{self.key_exchange_score} / 100" }
				Logger.info { "Ciphers strength : #{self.cipher_strengths_score} / 100" }
				Logger.info { "Overall score : #{self.score} / 100" }
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

				@grade = [@grade, 'B'].max if !@server.tlsv1_2? or @server.key_size < 2048
				@grade = [@grade, 'C'].max if @server.des3?
				@grade = [@grade, 'F'].max unless @error.empty?

				@grade = 'M' unless @server.cert_valid
				@grade = 'T' unless @server.cert_trusted

				@grade = 'A+' if @grade == 'A' and @error.empty? and @warning.empty? and (all_success & @success) == all_success
			end

			def calculate_error
				@error = []

				@error << :md5_sig if @server.md5_sig?

				@error << :md5 if @server.md5?

				@error << :anonymous if @server.anonymous?

				@error << :dss if @server.dss?

				@error << :null if @server.null?
				@error << :export if @server.export?
				@error << :des if @server.des?
				@error << :rc4 if @server.rc4?
			end

			def calculate_warning
				@warning = []

				@warning << :sha1_sig if @server.sha1_sig?

				#@warning << :sha1 if @server.sha1?

				@warning << :des3 if @server.des3?
			end

			def calculate_success
				@success = []
				@success << :pfs if @server.pfs_only?
			end

			ALL_ERROR = %i(md5_sig md5 anonymous dss null export des rc4)
			def all_error
				ALL_ERROR
			end

			ALL_WARNING = %i(sha1_sig des3)
			def all_warning
				ALL_WARNING
			end

			ALL_SUCCESS = %i(pfs)
			def all_success
				ALL_SUCCESS
			end

			METHODS_SCORES = { SSLv2: 0, SSLv3: 20, TLSv1: 60, TLSv1_1: 80, TLSv1_2: 100 }
			def calculate_protocol_score
				@protocol_score = @server.supported_protocols.collect { |p| METHODS_SCORES[p] }.min
			end

			def calculate_key_exchange_score
				@key_exchange_score = case @server.key_size
										  when 0 then 0
										  when 0...512 then 10
										  when 512...1024 then 20
										  when 1024...2048 then 50
										  when 2048...4096 then 90
										  else 100
									  end
			end

			def calculate_cipher_strengths_score
				@cipher_strengths_score = case @server.cipher_size
					when 0 then 0
					when 0...112 then 10
					when 112...128 then 50
					when 128...256 then 90
					else 100
				end
			end
		end
	end
end
