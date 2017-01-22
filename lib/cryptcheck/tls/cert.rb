module CryptCheck
	module Tls
		class Cert
			DEFAULT_CA_DIRECTORIES = [
					'/usr/share/ca-certificates/mozilla'
			]

			SIGNATURE_ALGORITHMS = {
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
			}

			%i(md2 mdc2 md4 md5 ripemd160 sha sha1 sha2 rsa dss ecc ghost).each do |name|
				class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
					def #{name}_sig?
						@chains.any? do |chain|
							SIGNATURE_ALGORITHMS[chain[:cert].signature_algorithm].include? :#{name}
						end
					end
				RUBY_EVAL
			end

			def self.trusted?(cert, chain, roots: DEFAULT_CA_DIRECTORIES)
				store         = ::OpenSSL::X509::Store.new
				store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
				store.add_chains roots
				chain.each do |cert|
					# Never add other self signed certificates than system CA !
					next if cert.subject == cert.issuer
					store.add_cert cert rescue nil
				end

				trusted = store.verify cert
				return :trusted if trusted
				store.error_string
			end
		end
	end
end
