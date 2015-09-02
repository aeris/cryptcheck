#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

name, port, level = case ARGV.length
	when 1 then [ARGV[0], 22, :info]
	when 2 then [ARGV[0], ARGV[1], :info]
	when 3 then [ARGV[0], ARGV[1], ARGV[3]]
end

::CryptCheck::Logger.level = level
server = ::CryptCheck::Ssh::Server.new name, port
#grade = ::CryptCheck::Ssh::Grade.new server
#::CryptCheck::Logger.info { '' }
#grade.display
