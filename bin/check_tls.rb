#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

::CryptCheck::Logger.level = (ARGV[2] || :info).to_sym
server = ::CryptCheck::Tls::TcpServer.new ARGV[0], ARGV[1]
grade = ::CryptCheck::Tls::Grade.new server
::CryptCheck::Logger.info { '' }
grade.display
