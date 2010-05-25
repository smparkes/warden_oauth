module Warden
  module OAuth2
  
    #
    # Holds all the information of the OAuth2 service.
    #
    class Config
      attr_accessor :provider_name
      
      def client_key(key = nil)
        unless key.nil?
          @client_key = key
        end
        @client_key
      end
      alias_method :client_key=, :client_key

      def client_secret(secret = nil)
        unless secret.nil?
          @client_secret = secret
        end
        @client_secret
      end
      alias_method :client_secret=, :client_secret

      def options(options = nil) 
        unless options.nil?
          @options = options
        end
        @options
      end
      alias_method :options=, :options

      def check_requirements
        if @client_key.nil? || @client_secret.nil?
          raise Warden::OAuth2::ConfigError.new("You need to specify the client key and the client secret")
        end
      end

    end

  end
end
