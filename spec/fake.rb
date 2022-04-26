require 'ffi'

module Fake
  extend FFI::Library
  ffi_lib 'fake'

  def self.freeze(time)
    self._freeze time.to_i
    return yield
  ensure
    self._unfreeze
  end
  require 'amazing_print'

  def self.getaddrinfo(host, *ips)
    args = ips.collect { |ip| [:string, ip] }
    self._mock_getaddrinfo host, ips.size, *args.flatten
    return yield
  ensure
    self._unmock_getaddrinfo
  end

  private

  def self._freeze(_)
    #This is a stub, used for indexing
  end

  def self._unfreeze
    #This is a stub, used for indexing
  end

  attach_function :_freeze, [:time_t], :void
  attach_function :_unfreeze, [], :void

  def self._mock_getaddrinfo(_, _, *_)
    #This is a stub, used for indexing
  end

  def self._unmock_getaddrinfo
    #This is a stub, used for indexing
  end

  attach_function :_mock_getaddrinfo, [:string, :size_t, :varargs], :void
  attach_function :_unmock_getaddrinfo, [], :void
end
