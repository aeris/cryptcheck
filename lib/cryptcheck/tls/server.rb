module CryptCheck
	module Tls
		class Server
			Method.each do |method|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{method.to_sym.downcase}?
						@supported_methods.detect { |m| m == :#{method.to_sym} }
					end
				RUBY_EVAL
			end

			Cipher::TYPES.each do |type, _|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{type}?
						uniq_supported_ciphers.any? { |c| c.#{type}? }
					end
				RUBY_EVAL
			end

			def ssl?
				sslv2? or sslv3?
			end

			def tls?
				tlsv1? or tlsv1_1? or tlsv1_2?
			end

			def tls_only?
				tls? and !ssl?
			end

			def tlsv1_2_only?
				tlsv1_2? and not ssl? and not tlsv1? and not tlsv1_1?
			end

			def pfs?
				uniq_supported_ciphers.any? { |c| c.pfs? }
			end

			def pfs_only?
				uniq_supported_ciphers.all? { |c| c.pfs? }
			end

			def ecdhe?
				uniq_supported_ciphers.any? { |c| c.ecdhe? }
			end

			def ecdhe_only?
				uniq_supported_ciphers.all? { |c| c.ecdhe? }
			end

			def aead?
				uniq_supported_ciphers.any? { |c| c.aead? }
			end

			def aead_only?
				uniq_supported_ciphers.all? { |c| c.aead? }
			end

			def sweet32?
				uniq_supported_ciphers.any? { |c| c.sweet32? }
			end

			def fallback_scsv?
				@fallback_scsv
			end

			def must_staple?
				@cert.extensions.any? { |e| e.oid == '1.3.6.1.5.5.7.1.24' }
			end

			include Statused

			CHECKS = [
					# Protocols
					[:ssl, -> (s) { s.ssl? }, :critical],
					[:tls12, -> (s) { s.tlsv1_2? }, :good],
					[:tls12_only, -> (s) { s.tlsv1_2_only? }, :perfect],

					# Ciphers
					[:dss, -> (s) { s.dss? }, :critical],
					[:anonymous, -> (s) { s.anonymous? }, :critical],
					[:null, -> (s) { s.null? }, :critical],
					[:export, -> (s) { s.export? }, :critical],
					[:des, -> (s) { s.des? }, :critical],
					[:md5, -> (s) { s.md5? }, :critical],

					[:rc4, -> (s) { s.rc4? }, :error],
					[:sweet32, -> (s) { s.sweet32? }, :error],

					[:no_pfs, -> (s) { not s.pfs_only? }, :warning],
					[:pfs, -> (s) { s.pfs? }, :good],
					[:pfs_only, -> (s) { s.pfs_only? }, :perfect],

					[:no_ecdhe, -> (s) { not s.ecdhe? }, :warning],
					[:ecdhe, -> (s) { s.ecdhe? }, :good],
					[:ecdhe_only, -> (s) { s.ecdhe_only? }, :perfect],

					[:aead, -> (s) { s.aead? }, :good],
					#[:aead_only, -> (s) { s.aead_only? }, :best],
			].freeze

			def checks
				checks = CHECKS
				unless self.fallback_scsv? == nil
					checks += [
							[:no_fallback_scsv, -> (s) { not s.fallback_scsv? }, :error],
							[:fallback_scsv, -> (s) { s.fallback_scsv? }, :good]
					]
				end
				checks
			end

			def children
				@certs + @dh
			end

			include Engine
		end

		class TcpServer < Server
			private
			def sock_type
				::Socket::SOCK_STREAM
			end
		end

		class UdpServer < Server
			private
			def sock_type
				::Socket::SOCK_DGRAM
			end
		end
	end
end
