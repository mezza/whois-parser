require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.auda.org.au record.
    class WhoisAudaOrgAu < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :skip_lastupdate,
          :scan_keyvalue,
      ]

      tokenizer :scan_available do
        if @input.skip(/^(No Data Found)|(NOT FOUND)\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :skip_lastupdate do
        if @input.skip(/>>>(.+?)<<<\n/)
          # Consume any disclaimer text that follows the last update line
          @input.skip(/\n+/)
          if @input.rest?
            @ast["field:disclaimer"] = _scan_lines_to_array(/(.+)(\n+)/).join("\n")
          end
        end
      end
    end

  end
end
