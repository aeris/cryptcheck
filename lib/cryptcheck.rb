require 'colorize'
require 'ipaddr'
require 'timeout'
require 'yaml'
require 'openssl'

module CryptCheck
  autoload :State, 'cryptcheck/state'
  autoload :Host, 'cryptcheck/host'
  autoload :Server, 'cryptcheck/server'
  autoload :TcpServer, 'cryptcheck/server'
  autoload :UdpServer, 'cryptcheck/server'
  autoload :Grade, 'cryptcheck/grade'
  autoload :Logger, 'cryptcheck/logger'
  autoload :Tls, 'cryptcheck/tls'
  module Tls
    autoload :Method, 'cryptcheck/tls/method'
    autoload :Cipher, 'cryptcheck/tls/cipher'
    autoload :Curve, 'cryptcheck/tls/curve'
    autoload :Cert, 'cryptcheck/tls/cert'
    autoload :CAA, 'cryptcheck/tls/caa'
    autoload :Engine, 'cryptcheck/tls/engine'
    autoload :Server, 'cryptcheck/tls/server'
    autoload :TcpServer, 'cryptcheck/tls/server'
    autoload :UdpServer, 'cryptcheck/tls/server'
    autoload :Host, 'cryptcheck/tls/host'

    autoload :Https, 'cryptcheck/tls/https'
    module Https
      autoload :Server, 'cryptcheck/tls/https/server'
      autoload :Host, 'cryptcheck/tls/https/host'
    end

    autoload :Xmpp, 'cryptcheck/tls/xmpp.rb'
    module Xmpp
      autoload :Server, 'cryptcheck/tls/xmpp/server'
      autoload :Host, 'cryptcheck/tls/xmpp/host'
    end

    autoload :Smtp, 'cryptcheck/tls/smtp'
    module Smtp
      autoload :Server, 'cryptcheck/tls/smtp/server'
      autoload :Host, 'cryptcheck/tls/smtp/host'
    end
  end

  autoload :Ssh, 'cryptcheck/ssh'
  module Ssh
    autoload :Packet, 'cryptcheck/ssh/packet'
    autoload :Server, 'cryptcheck/ssh/server'
    autoload :SshNotSupportedServer, 'cryptcheck/ssh/server'
  end

  def self.dev?
    @dev ||= !ENV['DEV_MODE'].nil?
  end
end

fixtures = File.join __dir__, 'fixtures', '**', '*.rb'
Dir[fixtures].sort.each { |f| require f }
