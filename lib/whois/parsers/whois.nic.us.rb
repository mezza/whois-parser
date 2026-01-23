#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'


module Whois
  class Parsers

    # Parser for the whois.nic.us server.
    #
    # @note .us domains follow ICANN compliant format
    #   with fields like Registry Domain ID, Registry Expiry Date, etc.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicUs < BaseIcannCompliant
      # Override status to return actual EPP status codes
      property_supported :status do
        Array(node("Domain Status")).map do |status|
          # Remove the URL part if present (e.g., "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited")
          status.split(/\s+/).first
        end
      end
    end

  end
end