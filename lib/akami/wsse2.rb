require 'time'
require 'base64'
require 'gyoku'
require 'digest/sha1'
require 'securerandom'

module Akami

  class Wsse2

    #region "Constants"
    NAMESPACES = {
        :wse => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
        :wsu => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
        :text_password => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText',
        :digest_password => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest',
        :base64 => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
    }
    CONFIG_KEYS = [
        :username,
        :password,
        :use_digest,
        :use_timestamp,
        :use_nonce,
        :use_created,
        :use_signature,
        :use_global_namespaces,
        :env_namespace
    ]

    attr_accessor :hash,
                  :attributes,
                  :username,
                  :password,
                  :use_digest,
                  :use_timestamp,
                  :use_nonce,
                  :use_created,
                  :use_signature,
                  :use_global_namespaces,
                  :env_namespace

    #endregion

    def initialize(params = {})
      params.each do |k,v|
        self.send("#{k}=", v) if CONFIG_KEYS.include? k
      end

      # Make sure soap envelope namespace is not blank
      if env_namespace.nil? or env_namespace.blank?
        self.env_namespace = 'soap'
      end
    end


    def use_digest?
      use_digest
    end

    def use_timestamp?
      use_timestamp
    end

    def use_nonce?
      use_nonce
    end

    def use_created?
      use_created
    end

    def use_signature?
      use_signature
    end

    def use_global_namespaces?
      use_global_namespaces
    end

    def to_xml
      Gyoku.xml build_wsse_header
    end

    private

      def build_wsse_header
        # Build the base hash
        self.hash = {
            'wsse:Security' => {
                :attributes! => {
                    'wsse:UsernameToken' => {
                        'wsu:Id' => "SecurityToken-#{SecureRandom.uuid}"
                    },
                    'wsu:Timestamp' => {
                        'wsu:Id' => "Timestamp-#{SecureRandom.uuid}"
                    }
                }
            }
        }

        # Merge namespaces unless using global namespaces
        hash.merge!({
            :attributes! => {
                'wsse:Security' => {
                    'xmlns:wsse' => NAMESPACES[:wse],
                    'xmlns:wsu' => NAMESPACES[:wsu]
                }
            }
        }) unless use_global_namespaces?

        # Merge signature if required
        if use_signature?
          hash[:attributes!] = {} unless hash[:attributes!].present?
          hash[:attributes!]['wsse:Security'] = {} unless hash[:attributes!]['wsse:Security'].present?
          hash[:attributes!]['wsse:Security'].merge!({ "#{env_namespace}:mustUnderstand" => '1' })
        end

        # Merge in UsernameToken
        hash['wsse:Security'].merge!({ 'wsse:UsernameToken' => build_username_token })

        # Merge in Timestamp if required
        hash['wsse:Security'].merge!({ 'wsse:Timestamp' => build_timestamp }) if use_timestamp?
        hash
      end

      def build_username_token
        # Build base hash
        token_hash = {
          'wsse:Username' => username,
          'wsse:Password' => (use_digest? ? digest_password : password),
          :attributes! => {
              'wsse:Password' => {
                  'Type' => (use_digest? ? NAMESPACES[:digest_password] : NAMESPACES[:text_password])
              }
          }
        }

        # Merge in nonce if using it
        token_hash.merge!({ 'wsse:Nonce' => nonce }) if use_nonce?
        # Merge in Created if using it
        token_hash.merge!({ 'wsu:Created' => current_timestamp }) if use_created?
        token_hash
      end

      def build_timestamp
        timestamp_hash = {
            'wsu:Created' => current_timestamp,
            'wsu:Expires' => current_timestamp(60)
        }
        # self.attributes.merge!({ 'wsse:Timestamp' => { 'wsu:Id' => "Timestamp-#{SecureRandom.uuid}" }})
        timestamp_hash
      end


      def digest_password
        token = nonce + current_timestamp + password
        Base64.encode64(Digest::SHA1.digest(token)).chomp!
      end

      def nonce
        Digest::SHA1.hexdigest random_string + current_timestamp
      end

      def current_timestamp(offset = nil)
        if offset.nil?
          Time.now.utc.xmlschema
        else
          (Time.now + offset).utc.xmlschema
        end
      end

      def random_string
        (0...100).map{ ('a'..'z').to_a[rand(26)] }.join
      end
  end

end