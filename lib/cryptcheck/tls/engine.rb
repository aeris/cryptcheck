require 'socket'
require 'openssl'

module CryptCheck
  module Tls
    module Engine
      SLOW_DOWN   = ENV.fetch('SLOW_DOWN', '0').to_i
      TCP_TIMEOUT = 10
      TLS_TIMEOUT = 2 * TCP_TIMEOUT

      class TLSException < ::StandardError
      end

      class TLSNotAvailableException < TLSException
        def to_s
          'TLS seems not supported on this server'
        end
      end

      class MethodNotAvailable < TLSException
      end

      class CipherNotAvailable < TLSException
      end

      class InappropriateFallback < TLSException
      end

      class Timeout < ::StandardError
        def initialize(ip, port)
          @message = "Timeout when connecting to #{ip}:#{port} (max #{TCP_TIMEOUT.humanize})"
        end

        def to_s
          @message
        end
      end

      class TLSTimeout < Timeout
        def initialize(ip, port)
          @message = "Timeout when TLS connecting to #{ip}:#{port} (max #{TLS_TIMEOUT.humanize})"
        end
      end

      class ConnectionError < ::StandardError
      end

      attr_reader :hostname, :ip, :family, :port, :certs, :keys, :dh,
                  :supported_methods, :supported_ciphers,
                  :supported_curves, :curves_preference

      def initialize(hostname, ip, family, port)
        @hostname, @ip, @family, @port = hostname, ip, family, port
        @dh                            = []

        @name = "#@ip:#@port"
        @name += " [#@hostname]" if @hostname

        Logger.info { @name.colorize :blue }

        fetch_supported_methods
        fetch_supported_ciphers
        fetch_dh
        fetch_ciphers_preferences
        fetch_ecdsa_certs
        fetch_supported_curves
        fetch_curves_preference

        check_fallback_scsv

        verify_certs
      end

      def supported_method?(method)
        ssl_client method
        Logger.info { "  Method #{method}" }
        true
      rescue TLSException
        Logger.debug { "  Method #{method} : not supported" }
        false
      rescue TLSTimeout
        raise if ENV['BUG_METHOD_UNSUPPORTED_TIMEOUT'].nil?
      end

      def fetch_supported_methods
        Logger.info { '' }
        Logger.info { 'Supported methods' }
        @supported_methods = Method.select { |m| supported_method? m }
        raise TLSNotAvailableException if @supported_methods.empty?
      end

      def supported_cipher?(method, cipher)
        connection = ssl_client method, cipher
        Logger.info { "  Cipher #{cipher}" }
        dh = connection.tmp_key
        Logger.info { "    PFS : #{dh}" } if dh
        connection
      rescue TLSException
        Logger.debug { "  Cipher #{cipher} : not supported" }
        nil
      end

      def fetch_supported_ciphers
        Logger.info { '' }
        Logger.info { 'Supported ciphers' }
        @supported_ciphers = @supported_methods.collect do |method|
          ciphers = Cipher[method].collect do |cipher|
            connection = supported_cipher? method, cipher
            next nil unless connection
            [cipher, connection]
          end.compact.to_h
          [method, ciphers]
        end.to_h
      end

      def fetch_ciphers_preferences
        Logger.info { '' }
        Logger.info { 'Cipher suite preferences' }

        @preferences = @supported_ciphers.collect do |method, ciphers|
          ciphers     = ciphers.keys
          preferences = if ciphers.size < 2
                          Logger.info { "  #{method}  : " + 'not applicable'.colorize(:unknown) }
                          nil
                        else
                          a, b, _ = ciphers
                          ab      = ssl_client(method, [a, b]).cipher.first
                          ba      = ssl_client(method, [b, a]).cipher.first
                          if ab != ba
                            Logger.info { "  #{method} : " + 'client preference'.colorize(:warning) }
                            :client
                          else
                            sort        = -> (a, b) do
                              connection = ssl_client method, [a, b]
                              cipher     = connection.cipher.first
                              cipher == a.name ? -1 : 1
                            end
                            preferences = ciphers.sort &sort
                            Logger.info { "  #{method}  : " + preferences.collect { |c| c.to_s :short }.join(', ') }
                            preferences
                          end
                        end
          [method, preferences]
        end.to_h
      end

      def fetch_dh
        @dh = @supported_ciphers.collect do |_, ciphers|
          ciphers.values.collect(&:tmp_key).select { |d| d.is_a? OpenSSL::PKey::DH }
        end.flatten.uniq &:fingerprint
      end

      def fetch_ecdsa_certs
        @ecdsa_certs = {}

        @supported_ciphers.each do |method, ciphers|
          ecdsa = ciphers.keys.detect &:ecdsa?
          next unless ecdsa
          ecdsa_curve = Curve.new ciphers[ecdsa].tmp_key.curve

          @ecdsa_certs = Curve.collect do |curve|
            begin
              connection = ssl_client method, ecdsa, curves: [curve, ecdsa_curve]
              [curve, connection]
            rescue TLSException
              nil
            end
          end.compact.to_h

          break
        end
      end

      def fetch_supported_curves
        Logger.info { '' }
        Logger.info { 'Supported elliptic curves' }
        @supported_curves = []

        ecdsa_curve = @ecdsa_certs.keys.first
        if ecdsa_curve
          # If we have an ECDSA cipher, we need at least the certificate curve to do handshake,
          # but with lowest priority to check for ECHDE and not just ECDSA

          @supported_ciphers.each do |method, ciphers|
            ecdsa = ciphers.keys.detect &:ecdsa?
            next unless ecdsa
            @supported_curves = Curve.select do |curve|
              if curve == ecdsa_curve
                # ECDSA curve is always supported
                Logger.info { "  ECC curve #{curve.name}" }
                next true
              end
              begin
                connection = ssl_client method, ecdsa, curves: [curve, ecdsa_curve]
                # Not too fast !!!
                # Handshake will **always** succeed, because ECDSA
                # curve is always supported.
                # So, we need to test for the real curve!
                # Treaky case : if server preference is enforced,
                # ECDSA curve can be prefered over ECDHE one and so
                # really supported curve can be detected as not supported :(

                dh               = connection.tmp_key
                negociated_curve = dh.curve
                supported        = ecdsa_curve != negociated_curve
                if supported
                  Logger.info { "  ECC curve #{curve.name}" }
                else
                  Logger.debug { "  ECC curve #{curve.name} : not supported" }
                end
                supported
              rescue TLSException
                false
              end
            end
            break
          end
        else
          # If we have no ECDSA ciphers, ECC supported are only ECDH ones
          # So peak an ECDH cipher and test all curves
          @supported_ciphers.each do |method, ciphers|
            ecdh = ciphers.keys.detect { |c| c.ecdh? or c.ecdhe? }
            next unless ecdh
            @supported_curves = Curve.select do |curve|
              begin
                ssl_client method, ecdh, curves: curve
                Logger.info { "  ECC curve #{curve.name}" }
                true
              rescue TLSException
                Logger.debug { "  ECC curve #{curve.name} : not supported" }
                false
              end
            end
            break
          end
        end
      end

      def fetch_curves_preference
        @curves_preference = if @supported_curves.size < 2
                               Logger.info { 'Curves preference : ' + 'not applicable'.colorize(:unknown) }
                               nil
                             else
                               method, cipher = @supported_ciphers.collect do |method, ciphers|
                                 cipher = ciphers.keys.detect { |c| c.ecdh? or c.ecdhe? }
                                 [method, cipher]
                               end.detect { |n| !n.nil? }

                               a, b, _ = @supported_curves
                               ab, ba  = [a, b], [b, a]
                               if cipher.ecdsa?
                                 # In case of ECDSA, add the cert key at the end
                                 # Or no negociation possible
                                 ecdsa_curve = @ecdsa_certs.keys.first
                                 ab << ecdsa_curve
                                 ba << ecdsa_curve
                               end
                               ab = ssl_client(method, cipher, curves: ab).tmp_key.curve
                               ba = ssl_client(method, cipher, curves: ba).tmp_key.curve
                               if ab != ba
                                 Logger.info { 'Curves preference : ' + 'client preference'.colorize(:warning) }
                                 :client
                               else
                                 sort        = lambda do |a, b|
                                   curves = [a, b]
                                   if cipher.ecdsa?
                                     # In case of ECDSA, add the cert key at the end
                                     # Or no negociation possible
                                     curves << ecdsa_curve
                                   end
                                   connection = ssl_client method, cipher, curves: curves
                                   curve      = connection.tmp_key.curve
                                   a == curve ? -1 : 1
                                 end
                                 preferences = @supported_curves.sort &sort
                                 Logger.info { 'Curves preference : ' + preferences.collect { |c| c.name }.join(', ') }
                                 preferences
                               end
                             end
      end

      def check_fallback_scsv
        Logger.info { '' }

        @fallback_scsv = false
        if @supported_methods.size > 1
          # We will try to connect to the not better supported method
          method = @supported_methods[1]
          begin
            ssl_client method, fallback: true
          rescue InappropriateFallback,
            CipherNotAvailable, # Seems some servers reply with "sslv3 alert handshake failure"…
            MethodNotAvailable # Seems some servers reply with "wrong version number"…
            @fallback_scsv = true
          end
        else
          @fallback_scsv = nil
        end

        text, color = case @fallback_scsv
                      when true
                        ['supported', :good]
                      when false
                        ['not supported', :error]
                      when nil
                        ['not applicable', :unknown]
                      end
        Logger.info { 'Fallback SCSV : ' + text.colorize(color) }
      end

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

      private

      def connect(&block)
        socket   = ::Socket.new @family, sock_type
        sockaddr = ::Socket.sockaddr_in @port, @ip
        #Logger.trace { "Connecting to #{@ip}:#{@port}" }
        begin
          status = socket.connect_nonblock sockaddr
          #Logger.trace { "Connecting to #{@ip}:#{@port} status : #{status}" }
          raise ConnectionError, status unless status == 0
          #Logger.trace { "Connected to #{@ip}:#{@port}" }
          block_given? ? block.call(socket) : nil
        rescue ::IO::WaitReadable
          #Logger.trace { "Waiting for read to #{@ip}:#{@port}" }
          raise Timeout.new(@ip, @port) unless IO.select [socket], nil, nil, TCP_TIMEOUT
          retry
        rescue ::IO::WaitWritable
          #Logger.trace { "Waiting for write to #{@ip}:#{@port}" }
          raise Timeout.new(@ip, @port) unless IO.select nil, [socket], nil, TCP_TIMEOUT
          retry
        rescue Errno::ECONNREFUSED => e
          raise ConnectionError, e
        ensure
          socket.close
        end
      end

      def ssl_connect(socket, context, method, &block)
        ssl_socket          = ::OpenSSL::SSL::SSLSocket.new socket, context
        ssl_socket.hostname = @hostname if @hostname and method != :SSLv2
        begin
          ssl_socket.connect_nonblock
          return block_given? ? block.call(ssl_socket) : nil
        rescue ::OpenSSL::SSL::SSLErrorWaitReadable
          raise TLSTimeout.new(@ip, @port) unless IO.select [ssl_socket], nil, nil, TLS_TIMEOUT
          retry
        rescue ::OpenSSL::SSL::SSLErrorWaitWritable
          raise TLSTimeout.new(@ip, @port) unless IO.select nil, [ssl_socket], nil, TLS_TIMEOUT
          retry
        rescue ::OpenSSL::SSL::SSLError => e
          case e.message
          when /state=SSLv2 read server hello A$/,
            /state=SSLv3 read server hello A$/,
            /state=SSLv3 read server hello A: wrong version number$/,
            /state=SSLv3 read server hello A: tlsv1 alert protocol version$/,
            /state=SSLv3 read server key exchange A: sslv3 alert handshake failure$/,
            /state=error: tlsv1 alert protocol version$/
            raise MethodNotAvailable, e
          when /state=SSLv2 read server hello A: peer error no cipher$/,
            /state=error: no ciphers available$/,
            /state=SSLv3 read server hello A: sslv3 alert handshake failure$/,
            /state=error: missing export tmp dh key$/,
            /state=error: wrong curve$/,
            /error: sslv3 alert handshake failure$/
            raise CipherNotAvailable, e
          when /state=SSLv3 read server hello A: tlsv1 alert inappropriate fallback$/,
            /state=error: tlsv1 alert inappropriate fallback$/
            raise InappropriateFallback, e
          end
          raise
        rescue ::SystemCallError => e
          case e.message
          when /^Connection reset by peer - SSL_connect$/
            raise TLSNotAvailableException, e
          end
          raise
        ensure
          ssl_socket.close
        end
      end

      def ssl_client(method, ciphers = nil, curves: nil, fallback: false, &block)
        sleep SLOW_DOWN if SLOW_DOWN > 0
        method      = method.to_sym
        ssl_context = ::OpenSSL::SSL::SSLContext.new method
        ssl_context.enable_fallback_scsv if fallback

        ciphers = Array(ciphers).collect(&:name).join ':' if ciphers

        if method == :TLSv1_3
          ssl_context.ciphersuites = ciphers if ciphers
        else
          ciphers             ||= Cipher::ALL
          ssl_context.ciphers = ciphers
        end

        if curves
          curves = [curves] unless curves.is_a? Enumerable
          # OpenSSL fails if the same curve is selected multiple times
          # So because Array#uniq preserves order, remove the less prefered ones
          curves                  = curves.collect(&:name).uniq.join ':'
          ssl_context.ecdh_curves = curves
        end

        Logger.trace { "Try method=#{method} / ciphers=#{ciphers} / curves=#{curves} / scsv=#{fallback}" }
        connect do |socket|
          ssl_connect socket, ssl_context, method do |ssl_socket|
            return block_given? ? block.call(ssl_socket) : ssl_socket
          end
        end
      rescue TLSException => e
        Logger.trace { "Error occurs : #{e}" }
        raise
      rescue => e
        Logger.trace { "Error occurs : #{e}" }
        raise TLSException.new e
      end

      def verify_certs
        Logger.info { '' }
        Logger.info { 'Certificates' }

        # Let's begin the fun
        # First, collect "standard" connections
        # { method => { cipher => connection, ... }, ... }
        certs = @supported_ciphers.values.collect(&:values).flatten 1
        # Then, collect "ecdsa" connections
        # { curve => connection, ... }
        certs += @ecdsa_certs.values
        # For anonymous cipher, there is no certificate at all
        certs = certs.reject { |c| c.peer_cert.nil? }
        # Then, fetch cert
        certs = certs.collect { |c| Cert.new c }
        # Then, filter cert to keep uniq fingerprint
        @certs = certs.uniq { |c| c.fingerprint }

        @trusted = @valid = true
        @certs.each do |cert|
          key      = cert.key
          identity = cert.valid?(@hostname || @ip)
          trust    = cert.trusted?
          Logger.info { "  Certificate #{cert.subject} [#{cert.serial}] issued by #{cert.issuer}" }
          Logger.info { '    Key : ' + Tls.key_to_s(key) }
          if identity
            Logger.info { '    Identity : ' + 'valid'.colorize(:good) }
          else
            Logger.info { '    Identity : ' + 'invalid'.colorize(:error) }
            @valid = false
          end
          if trust == :trusted
            Logger.info { '    Trust : ' + 'trusted'.colorize(:good) }
          else
            Logger.info { '    Trust : ' + 'untrusted'.colorize(:error) + ' - ' + trust }
            @trusted = false
          end
        end
        @keys = @certs.collect &:key
      end

      private

      def uniq_supported_ciphers
        @uniq_supported_ciphers ||= @supported_ciphers.values.collect(&:keys).flatten.uniq
      end
    end
  end
end
