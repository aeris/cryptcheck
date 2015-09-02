module CryptCheck
	module Ssh
		class Packet
			SSH_MSG_KEXINIT = 20

			def self.uint32(raw)
				raw.gets(4).unpack('N').first
			end

			def self.string(raw)
				length = self.uint32 raw
				raw.gets length
			end

			def self.strings(raw)
				self.string(raw).split ','
			end

			def self.read(socket)
				packet_length  = socket.recv(4).unpack('N').first
				padding_length = socket.recv(1).unpack('C').first
				payload        = socket.recv packet_length - padding_length - 1
				socket.recv padding_length
				StringIO.new payload
			end

			def self.read_kex_init(socket)
				payload = self.read socket
				msg_id  = payload.gets(1).unpack('C').first
				raise "Not expected message id #{msg_id}" unless msg_id == SSH_MSG_KEXINIT

				payload.gets 16 # cookie

				key_algorithms         = self.strings payload
				host_key_algorithms    = self.strings payload
				encryption_algorithms = (self.strings(payload) + self.strings(payload)).uniq
				mac_algorithms         = (self.strings(payload) + self.strings(payload)).uniq
				compression_algorithms = (self.strings(payload) + self.strings(payload)).uniq

				{ kex: key_algorithms, host_key: host_key_algorithms, encryption: encryption_algorithms,
				  mac: mac_algorithms, compression: compression_algorithms }
			end
		end
	end
end
