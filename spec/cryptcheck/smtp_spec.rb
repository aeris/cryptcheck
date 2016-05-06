describe CryptCheck::Tls::Smtp do
	def server(*args, **kargs, &block)
		kargs[:plain_process] = proc do |socket|
			socket.write "220 localhost\r\n"
			socket.gets
			socket.write "250-STARTTLS\r\n"
			socket.gets
			socket.write "220 Ready to start TLS\r\n"
			true
		end unless kargs.include? :plain_process
		starttls_serv *args, **kargs, &block
	end

	def plain_server(*args, **kargs, &block)
		kargs[:plain_process] = proc do |socket|
			socket.write "220 localhost\r\n"
			socket.gets
			socket.write "250 DONE\r\n"
			false
		end unless kargs.include? :plain_process
		starttls_serv *args, **kargs, &block
	end

	def analyze(*args)
		CryptCheck::Tls::Smtp.analyze *args
	end

	include_examples :analysis
end
