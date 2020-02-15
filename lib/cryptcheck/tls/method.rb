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

      def to_h
        { protocol: self.to_sym, states: self.states }
      end

      alias to_sym __getobj__

      def <=>(other)
        EXISTING.find_index(self) <=> EXISTING.find_index(other)
      end

      include State

      CHECKS = [
        [:sslv2, :critical, -> (s) { s == :SSLv2 }],
        [:sslv3, :critical, -> (s) { s == :SSLv3 }],
        [:tlsv1_0, :error, -> (s) { s == :TLSv1 }],
        [:tlsv1_1, :error, -> (s) { s == :TLSv1_1 }]
      ].freeze

      protected

      def available_checks
        CHECKS
      end
    end
  end
end
