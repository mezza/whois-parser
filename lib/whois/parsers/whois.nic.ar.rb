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

    # Parser for the whois.nic.ar server.
    class WhoisNicAr < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /El dominio no se encuentra registrado/)
      end

      property_supported :registered? do
        !available?
      end

      property_supported :created_on do
        if content_for_scanner =~ /registered:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /changed:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /expire:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :registrant_contacts do
        if content_for_scanner =~ /contact:\s+(.+)\nname:\s+(.+)\n/
          [Parser::Contact.new(
            type: Parser::Contact::TYPE_REGISTRANT,
            id:   ::Regexp.last_match(1).strip,
            name: ::Regexp.last_match(2).strip,
          )]
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(\S+)/).flatten.map do |name|
          Parser::Nameserver.new(name: name)
        end
      end

    end

  end
end
