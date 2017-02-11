require 'delegate'

module CryptCheck
	module Tls
		class Method < SimpleDelegator
			EXISTING  = %i(TLSv1_2 TLSv1_1 TLSv1 SSLv3 SSLv2).freeze
			SUPPORTED = (EXISTING & ::OpenSSL::SSL::SSLContext::METHODS)
								.collect { |m| [m, self.new(m)] }.to_h.freeze

			def self.[](method)
				SUPPORTED[method]
			end

			extend Enumerable

			def self.each(&block)
				SUPPORTED.values.each &block
			end

			def to_s
				colors = case self.to_sym
							 when *%i(SSLv3 SSLv2)
								 :critical
							 when :TLSv1_2
								 :good
						 end
				super.colorize colors
			end

			alias :to_sym :__getobj__

			def <=>(other)
				EXISTING.find_index(self) <=> EXISTING.find_index(other)
			end

			include State

			CHECKS = [
					[:sslv2, -> (s) { s == :SSLv2 }, :critical],
					[:sslv3, -> (s) { s == :SSLv3 }, :critical],
					[:tlsv1_2, -> (s) { s == :TLSv1_2 }, :good]
			]

			def checks
				CHECKS
			end
		end
	end
end
