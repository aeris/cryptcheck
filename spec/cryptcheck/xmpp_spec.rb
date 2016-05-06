describe CryptCheck::Tls::Xmpp do
	def server(*args, **kargs, &block)
		kargs[:plain_process] = proc do |socket|
			socket.gets
			socket.puts "<?xml version='1.0'?><stream:stream xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='localhost' id='' xml:lang='en' xmlns='jabber:server'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'></starttls><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
			socket.gets
			socket.puts "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' />"
			true
		end unless kargs.include? :plain_process
		starttls_serv *args, **kargs, &block
	end

	def plain_server(*args, **kargs, &block)
		kargs[:plain_process] = proc do |socket|
			socket.gets
			socket.puts "<?xml version='1.0'?><stream:stream xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='localhost' id='' xml:lang='en' xmlns='jabber:server'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'></starttls><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
			socket.gets
			socket.puts "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' />"
			false
		end unless kargs.include? :plain_process
		starttls_serv *args, **kargs, &block
	end

	def analyze(*args)
		CryptCheck::Tls::Xmpp.analyze *args, type: :s2s
	end

	include_examples :analysis do
		it 'return error on XMPP error' do
			plain_process = proc do |socket|
				socket.gets
				socket.puts "<?xml version='1.0'?><stream:stream xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='localhost' id='' xml:lang='en' xmlns='jabber:server'><stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"
				false
			end

			grades = server host: '127.0.0.1', plain_process: plain_process do
				analyze '127.0.0.1', 5000
			end

			expect_grade_error grades, '127.0.0.1', '127.0.0.1', 5000,
					'<invalid-namespace xmlns="urn:ietf:params:xml:ns:xmpp-streams"/>'
		end
	end

	describe '#required?' do
		it 'has TLS not required' do
			grades = server host: '127.0.0.1' do
				analyze '127.0.0.1', 5000
			end

			_, server = expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
			expect(server.required?).to be false
		end

		it 'has TLS required' do
			plain_process = proc do |socket|
				socket.gets
				socket.puts "<?xml version='1.0'?><stream:stream xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='localhost' id='' xml:lang='en' xmlns='jabber:server'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><dialback xmlns='urn:xmpp:features:dialback'/></stream:features>"
				socket.gets
				socket.puts "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' />"
				true
			end

			grades = server host: '127.0.0.1', plain_process: plain_process do
				analyze '127.0.0.1', 5000
			end

			_, server = expect_grade grades, '127.0.0.1', '127.0.0.1', 5000, :ipv4
			expect(server.required?).to be true
		end
	end
end
