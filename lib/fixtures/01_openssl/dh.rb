module Fixture
  module OpenSSL
    module DH
      def type
        :dh
      end

      def size
        self.p.num_bits
      end

      def to_s
        "DH #{self.size} bits"
      end

      def to_h
        { size: self.size, fingerprint: self.fingerprint, states: self.states }
      end

      protected

      include ::CryptCheck::State

      CHECKS = [
        [:dh, %i(critical error), -> (s) do
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

      protected

      def available_checks
        CHECKS
      end
    end
  end
end

::OpenSSL::PKey::DH.prepend Fixture::OpenSSL::DH
