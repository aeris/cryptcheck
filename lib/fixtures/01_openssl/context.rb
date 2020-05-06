module Fixture
  module OpenSSL
    if ::OpenSSL.ge_2_1_2?
      module Context
        METHODS  = {
          TLSv1_3: ::OpenSSL::SSL::TLS1_3_VERSION,
          TLSv1_2: ::OpenSSL::SSL::TLS1_2_VERSION,
          TLSv1_1: ::OpenSSL::SSL::TLS1_1_VERSION,
          TLSv1:   ::OpenSSL::SSL::TLS1_VERSION,
          SSL_3:   ::OpenSSL::SSL::SSL3_VERSION,
          SSL_2:   ::OpenSSL::SSL::SSL2_VERSION
        }.freeze
        EXCLUDES = {
          TLSv1_3: ::OpenSSL::SSL::OP_NO_TLSv1_3,
          TLSv1_2: ::OpenSSL::SSL::OP_NO_TLSv1_2,
          TLSv1_1: ::OpenSSL::SSL::OP_NO_TLSv1_1,
          TLSv1:   ::OpenSSL::SSL::OP_NO_TLSv1,
          SSL_3:   ::OpenSSL::SSL::OP_NO_SSLv3,
          SSL_2:   ::OpenSSL::SSL::OP_NO_SSLv2
        }.yield_self do |e|
          all = e.values
          e.collect do |m, o|
            excludes = all - [o]
            options  = excludes.reduce :|
            [m, options]
          end.to_h
        end.freeze

        module Prepend
          def initialize(method = nil)
            super()
            if method
              self.options     = EXCLUDES[method]
              self.min_version = self.max_version = METHODS[method]
            end
          end
        end

        module ClassMethods
          def supported?(method)
            return false if %i[SSLv2 SSLv3].include? method
            self.new method
            true
          rescue => e
            ap e
            false
          end
        end

        def self.included(base)
          base.extend ClassMethods
          base.prepend Prepend
        end
      end
    else
      module Context
        module ClassMethods
          def supported?(method)
            ::OpenSSL::SSL::SSLContext::METHODS.include? method
          end
        end

        def self.included(base)
          base.extend ClassMethods
        end
      end
    end
  end
end

::OpenSSL::SSL::SSLContext.include Fixture::OpenSSL::Context
