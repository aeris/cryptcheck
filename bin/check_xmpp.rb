#!/usr/bin/env ruby
$:.unshift File.expand_path File.join File.dirname(__FILE__), '../lib'
require 'rubygems'
require 'bundler/setup'
require 'cryptcheck'

args, type = ARGV
args = [args, type] if type
::CryptCheck::Tls::Xmpp.analyze *args
