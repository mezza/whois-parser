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

    # Parser for the whois.markmonitor.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisMarkmonitorCom < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^No match for/,
          pattern_throttled: /^You have exceeded your quota of queries\./,
      }

      protected

      def build_contact(element, type)
        if node("#{element} Name") || node("#{element} Organization")
          Parser::Contact.new(
            type:         type,
            id:           node("Registry #{element} ID").presence,
            name:         value_for_property(element, 'Name'),
            organization: contact_organization_attribute(element),
            address:      contact_address_attribute(element),
            city:         value_for_property(element, 'City'),
            zip:          value_for_property(element, 'Postal Code'),
            state:        value_for_property(element, 'State/Province'),
            country_code: value_for_property(element, 'Country'),
            phone:        value_for_phone_property(element, 'Phone'),
            fax:          value_for_phone_property(element, 'Fax'),
            email:        value_for_property(element, 'Email')
          )
        end
      end

    end

  end
end
