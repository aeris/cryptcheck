module CryptCheck
  module Tls
    class Cipher
      TYPES = {
        md5:       %w(MD5),
        sha1:      %w(SHA),
        sha256:    %w(SHA256),
        sha384:    %w(SHA384),
        poly1305:  %w(POLY1305),

        psk:       %w(PSK),
        srp:       %w(SRP),
        anonymous: %w(ADH AECDH),
        dss:       %w(DSS),
        rsa:       %w(RSA),
        ecdsa:     %w(ECDSA),
        dh:        %w(DH ADH),
        ecdh:      %w(ECDH AECDH),
        dhe:       %w(DHE EDH ADH),
        ecdhe:     %w(ECDHE AECDH),

        null:      %w(NULL),
        export:    %w(EXP),
        rc2:       %w(RC2),
        rc4:       %w(RC4),
        des:       %w(DES-CBC),
        des3:      %w(3DES DES-CBC3),
        aes:       %w(AES(128|256) AES-(128|256)),
        aes128:    %w(AES128 AES-128),
        aes256:    %w(AES256 AES-256),
        camellia:  %w(CAMELLIA(128|256)),
        seed:      %w(SEED),
        idea:      %w(IDEA),
        chacha20:  %w(CHACHA20),

        # cbc:      %w(CBC),
        gcm: %w(GCM),
        ccm: %w(CCM)
      }.freeze

      attr_reader :method, :name

      def initialize(method, name)
        name           = name.first if name.is_a? Array
        @method, @name = method, name
      end

      extend Enumerable

      def self.each(&block)
        SUPPORTED.each &block
      end

      def self.[](method)
        method = Method[method] if method.is_a? Symbol
        SUPPORTED[method]
      end

      TYPES.each do |name, ciphers|
        class_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
				def self.#{name}?(cipher)
					#{ciphers}.any? { |c| /(^|-)#\{c\}(-|$)/ =~ cipher }
				end
				def #{name}?
					#{ciphers}.any? { |c| /(^|-)#\{c\}(-|$)/ =~ @name }
				end
        RUBY_EVAL
      end

      def self.aes?(cipher)
        aes?(cipher) or aes?(cipher)
      end

      def aes?
        aes128? or aes256?
      end


      def self.cbc?(cipher)
        !aead? cipher
      end

      def cbc?
        !aead?
      end

      def self.aead?(cipher)
        gcm?(cipher) or ccm?(cipher)
      end

      def aead?
        gcm? or ccm? or chacha20?
      end

      def ssl?
        sslv2? or sslv3?
      end

      def tls?
        tlsv1? or tlsv1_1? or tlsv1_2?
      end

      def pfs?
        dhe? or ecdhe?
      end

      def ecc?
        ecdsa? or ecdhe? or ecdh?
      end

      def sweet32?
        size = self.encryption[1]
        return false unless size # Not block encryption
        size <= 64
      end

      def to_s(type = :long)
        case type
        when :long
          states = self.states.collect { |k, vs| vs.select { |_, c| c == true }.collect { |v| v.first.to_s.colorize k } }.flatten.join ' '
          "#{@method} #{@name.colorize self.status} [#{states}]"
        when :short
          @name.colorize self.status
        end
      end

      def to_h
        hmac = self.hmac
        {
          protocol:   @method, name: self.name, key_exchange: self.kex, authentication: self.auth,
          encryption: self.encryption,
          hmac:       { name: hmac.first, size: hmac.last }, states: self.states
        }
      end

      def <=>(other)
        compare = State.compare self, other
        return compare unless compare == 0

        size_a, size_b = a.size, b.size
        compare        = size_b <=> size_a
        return compare unless compare == 0

        dh_a, dh_b = a.dh, b.dh
        return -1 if not dh_a and dh_b
        return 1 if dh_a and not dh_b
        return a.name <=> b.name if not dh_a and not dh_b

        compare = b.dh.size <=> a.dh.size
        return compare unless compare == 0

        a.name <=> b.name
      end

      def self.list(cipher_suite = 'ALL:COMPLEMENTOFALL', method: :TLSv1_2)
        context         = OpenSSL::SSL::SSLContext.new method
        context.ciphers = cipher_suite
        ciphers         = context.ciphers.collect { |c| self.new method, c }
        ciphers.sort
      end

      def kex
        case
        when ecdhe? || ecdh?
          :ecdh
        when dhe? || dh?
          :dh
        when dss?
          :dss
        else
          :rsa
        end
      end

      def auth
        case
        when ecdsa?
          :ecdsa
        when rsa?
          :rsa
        when dss?
          :dss
        when anonymous?
          nil
        else
          :rsa
        end
      end

      def encryption
        case
        when chacha20?
          [:chacha20, 256, :stream, self.mode]
        when aes128?
          [:aes, 128, 128, self.mode]
        when aes256?
          [:aes, 256, 256, self.mode]
        when camellia?
          [:camellia, 128, 128, self.mode]
        when seed?
          [:seed, 128, 128, self.mode]
        when idea?
          [:idea, 128, 64, self.mode]
        when des3?
          [:'3des', 112, 64, self.mode]
        when des?
          [:des, 56, 64, self.mode]
        when rc4?
          [:rc4, 128, :stream, self.mode]
        when rc2?
          [:rc2, 64, 64, self.mode]
        when null?
          [nil, 0, 0, nil]
        end
      end

      def mode
        case
        when gcm?
          :gcm
        when ccm?
          :ccm
        when chacha20?
          :aead
        when rc4?
          nil
        else
          :cbc
        end
      end

      def hmac
        case
        when poly1305?
          [:poly1305, 128]
        when sha384?
          [:sha384, 384]
        when sha256?
          [:sha256, 256]
        when sha1?
          [:sha1, 160]
        when md5?
          [:md5, 128]
        end
      end

      protected

      include State

      CHECKS = [
        [:dss, :critical, -> (c) { c.dss? }],
        [:anonymous, :critical, -> (c) { c.anonymous? }],
        [:null, :critical, -> (c) { c.null? }],
        [:export, :critical, -> (c) { c.export? }],
        [:des, :critical, -> (c) { c.des? }],
        [:md5, :critical, -> (c) { c.md5? }],
        [:sha1, :warning, -> (c) { c.sha1? }],
        [:rc4, :critical, -> (c) { c.rc4? }],
        [:sweet32, :critical, -> (c) { c.sweet32? }],

        [:pfs, :error, -> (c) { not c.pfs? }],
        [:dhe, :warning, -> (c) { c.dhe? }],

        [:aead, :good, -> (c) { c.aead? }]
      ].freeze

      def available_checks
        CHECKS
      end

      def <=>(other)
        status = State.compare self, other
        return status if status != 0
        @name <=> other.name
      end

      ALL       = 'ALL:COMPLEMENTOFALL'.freeze
      SUPPORTED = Method.collect do |m|
        context         = ::OpenSSL::SSL::SSLContext.new m.to_sym
        context.ciphers = ALL
        ciphers         = context.ciphers.collect { |c| Cipher.new m, c.first }
        [m, ciphers.sort]
      end.to_h.freeze
    end
  end
end
