require 'timeout'

module SSLCheck
	class NoSslTlsGrade
		attr_reader :server, :score, :grade

		def initialize(server)
			@server, @score, @grade = server, -1, 'X'
		end
	end

	class Grade
		attr_reader :server, :score, :grade, :warning, :success

		def initialize(server)
			@server = server
			protocol_score
			key_exchange_score
			cipher_strengths_score
			@score = @protocol_score*0.3 +  @key_exchange_score*0.3 + @cipher_strengths_score*0.4
			calculate_grade
			warning
			success
			perfect
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
			@grade = [@grade, 'E'].max if @server.rc4? or @server.des?
			@grade = [@grade, 'F'].max if @server.ssl? or @server.key_size < 1024

			@grade = 'M' unless @server.cert_valid
			@grade = 'T' unless @server.cert_trusted
		end

		def warning
			@warning = []

			@warning << :md5_sig if @server.md5_sig?
			@warning << :sha1_sig if @server.sha1_sig?

			@warning << :md5 if @server.md5?
			#@warning << :sha1 if @server.sha1?

			@warning << :rc4 if @server.rc4?
			@warning << :des if @server.des?
			@warning << :des3 if @server.des3?
		end

		def success
			@success = []
			@success << :pfs if @server.pfs_only?
			@success << :hsts if @server.hsts?
			@success << :hsts_long if @server.hsts_long?
		end

		ALL_WARNING = %i(md5_sig md5 rc4 des)
		ALL_SUCCESS = %i(pfs hsts hsts_long)
		def perfect
			@grade = 'A+' if @grade == 'A' and (ALL_WARNING & @warning).empty? and (ALL_SUCCESS & @success) == ALL_SUCCESS
		end

		METHODS_SCORES = { SSLv2: 0, SSLv3: 80, TLSv1: 90, TLSv1_1: 95, TLSv1_2: 100 }
		def protocol_score
			methods = @server.supported_methods
			worst, best = methods[:worst], methods[:best]
			@protocol_score = (METHODS_SCORES[worst] + METHODS_SCORES[best]) / 2
		end

		def key_exchange_score
			@key_exchange_score = case @server.key_size
				when 0 then 0
				when 0...512 then 20
				when 512...1024 then 40
				when 1024...2048 then 80
				when 2048...4096 then 90
				else 100
			end
		end

		def cipher_strength_score(cipher_strength)
			case cipher_strength
				when 0 then 0
				when 0...128 then 20
				when 128...256 then 80
				else 100
			end
		end

		def cipher_strengths_score
			strength = @server.cipher_size
			worst, best = strength[:min], strength[:max]
			@cipher_strengths_score = (cipher_strength_score(worst) + cipher_strength_score(best)) / 2
		end
	end
end
