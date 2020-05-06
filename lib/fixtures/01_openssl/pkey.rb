require 'ostruct'

module Fixture
  module OpenSSL
    module PKey
      def fingerprint
        ::OpenSSL::Digest::SHA256.hexdigest self.to_der
      end

      # Currently, Ruby doesn't support curve other than NIST ECC
      # For X25519, we got a plain `PKey` instead of an `EC`
      # We need to wait for https://github.com/ruby/openssl/pull/329 &
      # https://github.com/ruby/openssl/pull/364 for more generic curve support
      # So we supposed we have X25519 in case we catch a `PKey`

      def type
        :x25519
      end

      def size
        128
      end

      def curve
        :x25519
      end

      def to_s
        "#{self.size} bits"
      end

      def to_h
        { type: :ecc, curve: self.curve, size: self.size, fingerprint: self.fingerprint, states: self.states }
      end

      include ::CryptCheck::State

      CHECKS = [].freeze

      def available_checks
        CHECKS
      end
    end
  end
end

::OpenSSL::PKey::PKey.include Fixture::OpenSSL::PKey
