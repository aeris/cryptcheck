module Fixture
  module OpenSSL
    module RSA
      def type
        :rsa
      end

      def size
        self.n.num_bits
      end

      def to_s
        "RSA #{self.size} bits"
      end

      def to_h
        { type: :rsa, size: self.size, fingerprint: self.fingerprint, states: self.states }
      end

      protected

      include ::CryptCheck::State

      CHECKS = [
        [:rsa, %i(critical error), ->(s) do
          case s.size
          when 0...1024
            :critical
          when 1024...2048
            :error
          else
            false
          end
        end]
      ].freeze

      def available_checks
        CHECKS
      end
    end
  end
end

::OpenSSL::PKey::RSA.include Fixture::OpenSSL::RSA
