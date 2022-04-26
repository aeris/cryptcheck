require 'socket'

class BasicServer
  def initialize(server, &block)
    @server = server
    @block  = block
    @thread = Thread.new { self.process }
  end

  def process
    loop do
      begin
        Thread.start(@server.accept) do |client|
          begin
            self.on_connect client
            @block.call client if @block
          ensure
            client.close
          end
        end
      rescue IOError
        break if @server.closed?
      rescue
      end
    end
  end

  def on_connect(_) end

  def close
    @server.close
    @thread.join
  end
end
