#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    #
    # = whois.nic.mx parser
    #
    # Parser for the whois.nic.mx server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisMx < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /Object_Not_Found/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created On:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      # FIXME: the response contains localized data
      # Expiration Date: 10-may-2011
      # Last Updated On: 15-abr-2010 <--
      # property_supported :updated_on do
      #   if content_for_scanner =~ /Last Updated On:\s+(.*)\n/
      #     parse_time($1)
      #   end
      # end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Administrative Contact", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Technical Contact", Parser::Contact::TYPE_TECHNICAL)
      end

      property_supported :nameservers do
        if content_for_scanner =~ /Name Servers:\n((.+\n)+)\n/
          ::Regexp.last_match(1).scan(/DNS:\s+(.+)\n/).flatten.map do |line|
            name, ipv4 = line.strip.split(/\s+/)
            Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
          end
        end
      end


      private

      def build_contact(element, type)
        if content_for_scanner =~ /#{element}:\n((\s+.+\n)+)/
          match = ::Regexp.last_match(1)
          name    = match[/Name:\s+(.+)/, 1]
          city    = match[/City:\s+(.+)/, 1]
          state   = match[/State:\s+(.+)/, 1]
          country = match[/Country:\s+(.+)/, 1]

          Parser::Contact.new(
            type:    type,
            name:    name,
            city:    city,
            state:   state,
            country: country,
          )
        end
      end

    end

  end
end
