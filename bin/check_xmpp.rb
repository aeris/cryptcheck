#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'
::CryptCheck::Tls::Xmpp.analyze_domain ARGV[0], type: ARGV.fetch(1, :s2s).to_sym
