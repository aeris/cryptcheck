require 'faketime'

describe CryptCheck::Tls::Server do
	before :all do
		FakeTime.freeze Time.utc(2000, 1, 1).to_i
	end

	after :all do
		FakeTime.unfreeze
	end

	describe '#md5_sign?' do
		it 'must detect server using MD5 certificate' do
			tls_serv do
				server = CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, '127.0.0.1', 5000
				expect(server.md5_sign?).to be false
			end

			tls_serv material: [:md5, [:rsa, 1024]] do
				server = CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, '127.0.0.1', 5000
				expect(server.md5_sign?).to be true
			end
		end
	end

	describe '#sha1_sign?' do
		it 'must detect server using SHA1 certificate' do
			tls_serv do
				server = CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, '127.0.0.1', 5000
				expect(server.sha1_sign?).to be false
			end

			tls_serv material: [:sha1, [:rsa, 1024]] do
				server = CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, '127.0.0.1', 5000
				expect(server.sha1_sign?).to be true
			end
		end
	end

	describe '#sha2_sign?' do
		it 'must detect server using SHA2 certificate' do
			tls_serv do
				server = CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, '127.0.0.1', 5000
				expect(server.sha2_sign?).to be true
			end

			tls_serv material: [:md5, :sha1] do
				server = CryptCheck::Tls::TcpServer.new 'localhost', ::Socket::PF_INET, '127.0.0.1', 5000
				expect(server.sha2_sign?).to be false
			end
		end
	end
end
