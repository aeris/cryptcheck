module CryptCheck
  module Ssh
    autoload :Host, 'cryptcheck/ssh/host'
    autoload :Server, 'cryptcheck/ssh/server'
    autoload :Grade, 'cryptcheck/ssh/grade'

    def self.analyze(host, port = 22)
      host = Host.new host, port
      Tls.aggregate host
    end
  end
end
