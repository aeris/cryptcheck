module CryptCheck
  module Tls
    module Xmpp
      class Host < CryptCheck::Host
        attr_reader :domain

        def initialize(*args, domain: nil, type: :s2s)
          @domain, @type = domain, type
          super *args
        end

        private

        def server(*args)
          Xmpp::Server.new *args, domain: @domain, type: @type
        end
      end
    end
  end
end
