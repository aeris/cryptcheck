require 'ffi'

module FakeTime
	extend FFI::Library
	ffi_lib 'faketime'

	def self._freeze(_)
		#This is a stub, used for indexing
	end
	def self.unfreeze
		#This is a stub, used for indexing
	end

	attach_function :_freeze, [:ulong], :void
	attach_function :unfreeze, [], :void

	def self.freeze(time)
		self._freeze time.to_i
		if block_given?
			begin
				return yield
			ensure
				self.unfreeze
			end
		end
	end
end
