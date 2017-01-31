require 'faketime'

describe CryptCheck::Tls::Server do
	before :all do
		FakeTime.freeze Time.utc(2000, 1, 1)
	end

	after :all do
		FakeTime.unfreeze
	end

	def server
		CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, '127.0.0.1', 5000
	end

	describe '#certs' do
		it 'must detect RSA certificate' do
			tls_serv material: [[:rsa, 1024]] do
				certs = server.certs.collect &:fingerprint
				expect(certs).to contain_exactly 'a11802a4407aaeb93ccd0bd8c8a61be17eaba6b378433af5ad45ecbb1d633f71'
			end
		end

		it 'must detect ECDSA certificate' do
			tls_serv material: [[:ecdsa, :prime256v1]] do
				certs = server.certs.collect &:fingerprint
				expect(certs).to contain_exactly '531ab9545f052818ff0559f648a147b104223834cc8f780516b3aacf1fdc8c06'
			end
		end

		it 'must detect RSA and ECDSA certificates' do
			tls_serv material: [[:ecdsa, :prime256v1], [:rsa, 1024]] do
				certs = server.certs.collect &:fingerprint
				expect(certs).to contain_exactly '531ab9545f052818ff0559f648a147b104223834cc8f780516b3aacf1fdc8c06',
												 'a11802a4407aaeb93ccd0bd8c8a61be17eaba6b378433af5ad45ecbb1d633f71'
			end
		end
	end

	describe '#supported_curves' do
		it 'must detect no supported curves' do
			tls_serv material: [[:rsa, 1024]], ciphers: %w(AES128-GCM-SHA256) do
				curves = server.supported_curves.collect &:name
				expect(curves).to be_empty
			end
		end

		it 'must detect supported curves for RSA' do
			tls_serv material: [[:rsa, 1024]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1 sect571r1) do
				curves = server.supported_curves.collect &:name
				expect(curves).to contain_exactly :prime256v1, :sect571r1
			end
		end

		it 'must detect supported curves from ECDSA' do
			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1), server_preference: false do
				curves = server.supported_curves.collect &:name
				expect(curves).to contain_exactly :prime256v1
			end
		end

		it 'must detect supported curves from ECDSA and ECDHE' do
			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1 sect571r1), server_preference: false do
				curves = server.supported_curves.collect &:name
				expect(curves).to contain_exactly :prime256v1, :sect571r1
			end
		end

		# No luck here :'(
		it 'can\'t detect supported curves from ECDHE if server preference enforced' do
			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1 sect571r1), server_preference: true do
				curves = server.supported_curves.collect &:name
				expect(curves).to contain_exactly :prime256v1
			end

			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(sect571r1 prime256v1), server_preference: true do
				curves = server.supported_curves.collect &:name
				expect(curves).to contain_exactly :prime256v1, :sect571r1
			end
		end
	end

	describe '#curves_preference' do
		it 'must report N/A if no curve on RSA' do
			tls_serv material:          [[:rsa, 1024]], ciphers: %w(AES128-GCM-SHA256),
					 server_preference: true do
				curves = server.curves_preference
				expect(curves).to be_nil
			end

			tls_serv material:          [[:rsa, 1024]], ciphers: %w(AES128-GCM-SHA256),
					 server_preference: false do
				curves = server.curves_preference
				expect(curves).to be_nil
			end
		end

		it 'must report N/A if a single curve on RSA' do
			tls_serv material: [[:rsa, 1024]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1), server_preference: true do
				curves = server.curves_preference
				expect(curves).to be_nil
			end

			tls_serv material: [[:rsa, 1024]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1), server_preference: false do
				curves = server.curves_preference
				expect(curves).to be_nil
			end
		end

		it 'must report server preference if server preference enforced on RSA' do
			tls_serv material: [[:rsa, 1024]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1 sect571r1), server_preference: true do
				curves = server.curves_preference.collect &:name
				expect(curves).to eq %i(prime256v1 sect571r1)
			end

			tls_serv material: [[:rsa, 1024]], ciphers: %w(ECDHE+AES),
					 curves:   %i(sect571r1 prime256v1), server_preference: true do
				curves = server.curves_preference.collect &:name
				expect(curves).to eq %i(sect571r1 prime256v1)
			end
		end

		it 'must report client preference if server preference not enforced on RSA' do
			tls_serv material: [[:rsa, 1024]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1 sect571r1), server_preference: false do
				curves = server.curves_preference
				expect(curves).to be :client
			end

			tls_serv material: [[:rsa, 1024]], ciphers: %w(ECDHE+AES),
					 curves:   %i(sect571r1 prime256v1), server_preference: false do
				curves = server.curves_preference
				expect(curves).to be :client
			end
		end

		it 'must report N/A if a single curve on ECDSA' do
			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1), server_preference: true do
				curves = server.curves_preference
				expect(curves).to be_nil
			end

			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1), server_preference: false do
				curves = server.curves_preference
				expect(curves).to be_nil
			end
		end

		# No luck here :'(
		it 'can\'t detect server preference if server preference enforced on ECDSA with preference on ECDSA curve' do
			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1 sect571r1), server_preference: true do
				curves = server.curves_preference
				expect(curves).to be_nil
			end
		end

		it 'must report server preference if server preference enforced on ECDSA with preference not on ECDSA curve' do
			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(sect571r1 prime256v1), server_preference: true do
				curves = server.curves_preference.collect &:name
				expect(curves).to eq %i(sect571r1 prime256v1)
			end
		end

		it 'must report client preference if server preference not enforced on ECDSA' do
			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(prime256v1 sect571r1), server_preference: false do
				curves = server.curves_preference
				expect(curves).to be :client
			end

			tls_serv material: [[:ecdsa, :prime256v1]], ciphers: %w(ECDHE+AES),
					 curves:   %i(sect571r1 prime256v1), server_preference: false do
				curves = server.curves_preference
				expect(curves).to be :client
			end
		end
	end

	describe '#md5_sign?' do
		it 'must detect server using MD5 certificate' do
			tls_serv do
				expect(server.md5_sign?).to be false
			end

			tls_serv material: [:md5, [:rsa, 1024]] do
				expect(server.md5_sign?).to be true
			end
		end
	end

	describe '#sha1_sign?' do
		it 'must detect server using SHA1 certificate' do
			tls_serv do
				expect(server.sha1_sign?).to be false
			end

			tls_serv material: [:sha1, [:rsa, 1024]] do
				expect(server.sha1_sign?).to be true
			end
		end
	end

	describe '#sha2_sign?' do
		it 'must detect server using SHA2 certificate' do
			tls_serv do
				expect(server.sha2_sign?).to be true
			end

			tls_serv material: [:md5, :sha1] do
				expect(server.sha2_sign?).to be false
			end
		end
	end
end
