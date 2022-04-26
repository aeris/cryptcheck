require 'socket'
require_relative 'basic_server'

class TcpServer < BasicServer
  def initialize(*args, &block)
    server = ::TCPServer.new *args
    super server, &block
  end
end
