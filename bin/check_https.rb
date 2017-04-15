#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'
::CryptCheck::Tls::Https::Host.new ARGV[0], ARGV.fetch(1, 443)
