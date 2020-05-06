module Fixture
  module OpenSSL
    module DSA
      def type
        :dsa
      end

      def size
        self.p.num_bits
      end

      def to_s
        "DSA #{self.size} bits"
      end

      def to_h
        { type: :dsa, size: self.size, fingerprint: self.fingerprint, states: self.states }
      end

      include ::CryptCheck::State

      CHECKS = [
        [:dsa, :critical, -> (_) { true }]
      ].freeze

      protected

      def available_checks
        CHECKS
      end
    end
  end
end

::OpenSSL::PKey::DSA.include Fixture::OpenSSL::DSA
