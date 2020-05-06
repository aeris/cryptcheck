module Fixture
  module OpenSSL
    module EC
      def type
        :ecc
      end

      def size
        self.group.degree
      end

      def curve
        self.group.curve_name
      end

      def to_s
        "ECC #{self.size} bits"
      end

      def to_h
        { type: :ecc, curve: self.curve, size: self.size, fingerprint: self.fingerprint, states: self.states }
      end

      protected

      include ::CryptCheck::State

      CHECKS = [
        [:ecc, %i(critical error warning), -> (s) do
          case s.size
          when 0...160
            :critical
          when 160...192
            :error
          when 192...256
            :warning
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

::OpenSSL::PKey::EC.include Fixture::OpenSSL::EC
