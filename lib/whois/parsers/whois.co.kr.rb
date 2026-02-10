#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'
require 'whois/scanners/whois.co.kr'


module Whois
  class Parsers

    # Parser for the whois.co.kr server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisCoKr < BaseIcannCompliant

      self.scanner = Scanners::WhoisCoKr, {
          pattern_available: /^No Data Found/,
      }

    end

  end
end
