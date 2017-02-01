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

			# def eql?(other)
			# 	self.to_sym.eql? other.to_sym
			# end
			#
			# def equal?(other)
			# 	self.to_sym.equal? other.to_sym
			# end
		end
	end
end
