module Fixture
  module OpenSSL
    module Certificate
      def fingerprint
        ::OpenSSL::Digest::SHA256.hexdigest self.to_der
      end
    end
  end
end

::OpenSSL::X509::Certificate.include Fixture::OpenSSL::Certificate
