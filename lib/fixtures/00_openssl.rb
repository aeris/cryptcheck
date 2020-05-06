module Fixture
  module OpenSSL
    module ClassMethods
      def version
        Gem::Version.new ::OpenSSL::VERSION
      end

      def ge?(version)
        self.version >= Gem::Version.new(version)
      end

      def ge_2_1_2?
        self.ge? '2.1.2'
      end
    end

    def self.included(base)
      base.extend ClassMethods
    end
  end
end

::OpenSSL.include Fixture::OpenSSL
