#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.fi.rb'


module Whois
  class Parsers

    # Parser for the whois.fi server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisFi < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisFi


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        if reserved?
          :reserved
        elsif registered?
          case node("status", &:downcase)
          when "registered"
            :registered
          when "granted"
            :registered
          when "grace period"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{node('status')}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("created") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("modified") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("expires") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Registrar") do |hash|
          Parser::Registrar.new(
            name:         hash['registrar'],
            url:          hash['www']
          )
        end
      end

      property_supported :registrant_contacts do
        build_holder_contact(Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_holder_contact(Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        node("Tech") do |hash|
          Parser::Contact.new(
            type:         Parser::Contact::TYPE_TECHNICAL,
            name:         hash['name'],
            email:        hash['email']
          )
        end
      end


      property_supported :nameservers do
        node('Nameservers') do |hash|
          Array(hash['nserver']).map do |line|
            Parser::Nameserver.new(name: line.split(" ").first)
          end
        end
      end

      # NEWPROPERTY
      def reserved?
        !!content_for_scanner.match(/Domain not available/)
      end

      private

      def build_holder_contact(type)
        node("Holder") do |hash|
          address = Array(hash['address'])
          Parser::Contact.new(
            type:         type,
            id:           hash['register number'],
            name:         hash['name'],
            address:      address.first,
            zip:          hash['postal'] || address[1],
            city:         hash['city'] || address[2],
            country:      hash['country'],
            phone:        hash['phone'],
            email:        hash['holder email']
          )
        end
      end

    end

  end
end
