module Fixture
  module OpenSSL
    module Store
      def add_chains(chains)
        chains = [chains] unless chains.is_a? Enumerable
        chains.each do |chain|
          case chain
          when ::OpenSSL::X509::Certificate
            self.add_cert chain
          else
            next unless File.exists? chain
            if File.directory?(chain)
              Dir.entries(chain)
                .collect { |e| File.join chain, e }
                .select { |e| File.file? e }
                .each { |f| self.add_file f }
            else
              self.add_file chain
            end
          end
        end
      end
    end
  end
end

::OpenSSL::X509::Store.include Fixture::OpenSSL::Store
