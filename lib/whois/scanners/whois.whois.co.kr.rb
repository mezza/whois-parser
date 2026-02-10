require_relative 'base_icann_compliant'

module Whois
  module Scanners

    # Scanner for whois.whois.co.kr records.
    #
    # The registrar's WHOIS response uses "Domain Name :" (with a space
    # before the colon) which the default skip_head tokenizer doesn't match.
    class WhoisWhoisCoKr < BaseIcannCompliant

      tokenizer :skip_head do
        if @input.scan(/\s*Domain Name\s*:\s*(.+)\n/)
          @ast["Domain Name"] = @input[1].strip
        end
      end

    end

  end
end
