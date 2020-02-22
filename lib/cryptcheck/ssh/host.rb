module CryptCheck
  module Ssh
    class Host < CryptCheck::Host
      private

      def server(*args)
        Ssh::Server.new *args
      end
    end
  end
end
