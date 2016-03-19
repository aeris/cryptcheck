#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

puts 'Supported methods'
puts OpenSSL::SSL::SSLContext::METHODS.select { |m| CryptCheck::Tls::Server::EXISTING_METHODS.include? m  }.sort.join ' '

puts 'Supported ciphers'
puts CryptCheck::Tls::Cipher.list.collect { |c| c.colorize }.join ' '
