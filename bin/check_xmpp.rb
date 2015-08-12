#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'logging'
require 'cryptcheck'

name = ARGV[0]
if name
	::CryptCheck::Logger.level = :info
	server = ::CryptCheck::Tls::Xmpp::Server.new(name, ARGV[1] || :s2s)
	grade = ::CryptCheck::Tls::Xmpp::Grade.new(server)
	::CryptCheck::Logger.info { '' }
	grade.display
else
	::CryptCheck::Logger.level = :none
	::CryptCheck::Tls::Xmpp.analyze_from_file 'output/xmpp.yml', 'output/xmpp.html'
end

