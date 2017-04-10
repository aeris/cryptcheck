module CryptCheck
	module Tls
		class Cert
			DEFAULT_CA_DIRECTORIES = [
					'/usr/share/ca-certificates/mozilla'
			]

			SIGNATURE_ALGORITHMS      = %i(md2 mdc2 md4 md5 ripemd160 sha sha1 sha2 rsa dss ecc ghost).freeze
			SIGNATURE_ALGORITHMS_X509 = {
					'dsaWithSHA'                             => %i(sha1 dss),
					'dsaWithSHA1'                            => %i(sha1 dss),
					'dsaWithSHA1_2'                          => %i(sha1 dss),
					'dsa_with_SHA224'                        => %i(sha2 dss),
					'dsa_with_SHA256'                        => %i(sha2 dss),

					'mdc2WithRSA'                            => %i(mdc2 rsa),

					'md2WithRSAEncryption'                   => %i(md2 rsa),

					'md4WithRSAEncryption'                   => %i(md4, rsa),

					'md5WithRSA'                             => %i(md5 rsa),
					'md5WithRSAEncryption'                   => %i(md5 rsa),

					'shaWithRSAEncryption'                   => %i(sha rsa),
					'sha1WithRSA'                            => %i(sha1 rsa),
					'sha1WithRSAEncryption'                  => %i(sha1 rsa),
					'sha224WithRSAEncryption'                => %i(sha2 rsa),
					'sha256WithRSAEncryption'                => %i(sha2 rsa),
					'sha384WithRSAEncryption'                => %i(sha2 rsa),
					'sha512WithRSAEncryption'                => %i(sha2 rsa),

					'ripemd160WithRSA'                       => %i(ripemd160 rsa),

					'ecdsa-with-SHA1'                        => %i(sha1 ecc),
					'ecdsa-with-SHA224'                      => %i(sha2 ecc),
					'ecdsa-with-SHA256'                      => %i(sha2 ecc),
					'ecdsa-with-SHA384'                      => %i(sha2 ecc),
					'ecdsa-with-SHA512'                      => %i(sha2 ecc),

					'id_GostR3411_94_with_GostR3410_2001'    => %i(ghost),
					'id_GostR3411_94_with_GostR3410_94'      => %i(ghost),
					'id_GostR3411_94_with_GostR3410_94_cc'   => %i(ghost),
					'id_GostR3411_94_with_GostR3410_2001_cc' => %i(ghost)
			}.freeze
			WEAK_SIGN                 = {
					critical: %i(mdc2 md2 md4 md5 sha sha1)
			}.freeze

			SIGNATURE_ALGORITHMS.each do |name|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{name}?
						SIGNATURE_ALGORITHMS_X509[@cert.signature_algorithm].include? :#{name}
					end
				RUBY_EVAL
			end

			def initialize(cert, chain=[])
				@cert, @chain = case cert
									when ::OpenSSL::X509::Certificate
										[cert, chain]
									when ::OpenSSL::SSL::SSLSocket
										[cert.peer_cert, cert.peer_cert_chain]
								end
			end

			def self.trusted?(cert, chain, roots: DEFAULT_CA_DIRECTORIES)
				store         = ::OpenSSL::X509::Store.new
				store.purpose = ::OpenSSL::X509::PURPOSE_SSL_SERVER
				store.add_chains roots
				chain.each do |cert|
					# Never add other self signed certificates than system CA !
					next if cert.subject == cert.issuer
					store.add_cert cert rescue nil
				end if chain

				trusted = store.verify cert
				return :trusted if trusted
				store.error_string
			end

			def trusted?(roots: DEFAULT_CA_DIRECTORIES)
				Cert.trusted? @cert, @chain, roots: roots
			end

			def valid?(host)
				::OpenSSL::SSL.verify_certificate_identity @cert, host
			end

			def fingerprint
				::OpenSSL::Digest::SHA256.hexdigest @cert.to_der
			end

			def key
				@cert.public_key
			end

			def subject
				@cert.subject
			end

			def serial
				@cert.serial
			end

			def issuer
				@cert.issuer
			end

			def lifetime
				{ not_before: @cert.not_before, not_after: @cert.not_after }
			end

			def to_h
				{
						subject:     self.subject.to_s,
						serial:      self.serial.to_s,
						issuer:      self.issuer.to_s,
						lifetime:    self.lifetime,
						fingerprint: self.fingerprint,
						chain:       @chain.collect do |cert|
							{
									subject:  cert.subject.to_s,
									serial:   cert.serial.to_s,
									issuer:   cert.issuer.to_s,
									lifetime: { not_before: cert.not_before, not_after: cert.not_after }
							}
						end,
						key:         self.key.to_h,
						states:      self.states
				}
			end

			protected
			include State

			CHECKS = WEAK_SIGN.collect do |level, hashes|
				hashes.collect do |hash|
					["#{hash}_sign".to_sym, level, -> (s) { s.send "#{hash}?" }]
				end
			end.flatten(1).freeze

			def available_checks
				CHECKS
			end

			def children
				[self.key]
			end
		end
	end
end
