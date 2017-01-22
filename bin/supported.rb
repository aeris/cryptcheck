#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

puts 'Supported methods'
puts CryptCheck::Tls::Method::SUPPORTED.sort.collect(&:to_s).join ' '

CryptCheck::Tls::Cipher.each do |method, ciphers|
	puts
	puts "#{ciphers.size} supported ciphers for #{method}"
	ciphers.sort.each do |cipher|
		puts "  #{cipher}"
	end
end
