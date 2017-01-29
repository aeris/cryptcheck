require 'ffi'

module FakeTime
	extend FFI::Library
	ffi_lib 'faketime'

	def self.freeze(_)
		#This is a stub, used for indexing
	end
	def self.unfreeze
		#This is a stub, used for indexing
	end

	attach_function :freeze, [:ulong], :void
	attach_function :unfreeze, [], :void

	def self.freeze_during(time, &block)
		self.freeze time.to_i
		begin
			return block.call
		ensure
			self.unfreeze
		end
	end
end
