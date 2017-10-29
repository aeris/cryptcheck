#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
Bundler.require :default, :development
require 'cryptcheck'

class CryptCheck::Tls::Cert
	def valid?(*_)
		true
	end

	def trusted?
		:trusted
	end
end

# obj = Class.new do
# 	include ::CryptCheck::State
#
# 	def available_checks
# 		[[:foo, %i(critical warning good best), -> (_) { :best }]]
# 	end
# end.new
# ap obj.states
# ap obj.status

# cipher = ::CryptCheck::Tls::Cipher[::CryptCheck::Tls::Method[:TLSv1_2]].first
# ap cipher.states
# ap cipher.status
# ap cipher.name
# puts cipher.to_s

# key = OpenSSL::PKey.read File.read 'spec/resources/rsa-1024.pem'
# ap key.states
# ap key.status

host = CryptCheck::Tls::Https::Host.new 'localhost', 443
