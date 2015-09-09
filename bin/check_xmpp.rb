#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

name, type, level = case ARGV.length
						when 1 then [ARGV[0], :s2s, :info]
						when 2 then [ARGV[0], ARGV[1].to_sym, :info]
						when 3 then [ARGV[0], ARGV[1].to_sym, ARGV[2].to_sym]
					end

if name
	::CryptCheck::Logger.level = level
	server = ::CryptCheck::Tls::Xmpp::Server.new name, type
	grade = ::CryptCheck::Tls::Xmpp::Grade.new server
	::CryptCheck::Logger.info { '' }
	grade.display
else
	::CryptCheck::Logger.level = :none
	::CryptCheck::Tls::Xmpp.analyze_from_file 'output/xmpp.yml', 'output/xmpp.html'
end

