require_relative 'base_icann_compliant'

module Whois
  module Scanners

    # Scanner for whois.co.kr records.
    #
    # The response from whois.co.kr contains two sections:
    # 1. The VeriSign thin WHOIS (no contact data)
    # 2. The registrar thick WHOIS (with full contact data)
    #
    # This scanner skips past the first section to parse
    # only the registrar's thick WHOIS data.
    class WhoisCoKr < BaseIcannCompliant

      tokenizer :skip_head do
        # Skip everything up to and including the VeriSign thin WHOIS section
        # and the disclaimer text, stopping at the registrar's "Domain Name" line.
        if @input.skip_until(/Registrars\.\n/)
          if @input.scan(/Domain Name\s*:\s*(.+)\n/)
            @ast["Domain Name"] = @input[1].strip
          end
        elsif @input.scan(/\s*Domain Name:\s*(.+)\n/)
          @ast["Domain Name"] = @input[1].strip
        end
      end

    end

  end
end
