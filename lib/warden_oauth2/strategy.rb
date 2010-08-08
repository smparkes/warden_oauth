module Warden
  module OAuth2

    #
    # Holds all the main logic of the OAuth2 authentication, all the generated
    # OAuth2 classes will extend from this class
    #
    class Strategy < Warden::Strategies::Base
      extend StrategyBuilder

      ######################
      ### Strategy Logic ###
      ######################


      def self.access_token_user_finders
        (@_user_token_finders ||= {})
      end

      #
      # An OAuth2 strategy will be valid to execute if:
      # * A 'warden_oauth2_provider' parameter is given, with the name of the OAuth2 service
      # * A 'oauth_token' is being receive on the request (response from an OAuth2 provider)
      #
      def valid?
        (params.include?('warden_oauth2_provider') &&  params['warden_oauth2_provider'] == config.provider_name.to_s) ||
          params.include?('code') 
      end


      #
      # Manages the OAuth2 authentication process, there can be 3 outcomes from this Strategy:
      # 1. The OAuth2 credentials are invalid and the FailureApp is called
      # 2. The OAuth2 credentials are valid, but there is no user associated to them. In this case
      #    the FailureApp is called, but the env['warden.options'][:oauth2][:access_token] will be 
      #    available.
      # 3. The OAuth2 credentials are valid, and the user is authenticated successfuly
      #
      # @note
      # If you want to signup users with the twitter credentials, you can manage the creation of a new 
      # user in the FailureApp with the given access_token
      #
      def authenticate!
        if params.include?('warden_oauth2_provider')
          # store_request_token_on_session
          redirect!(client.web_server.authorize_url(
            :redirect_uri => redirect_uri,
            :scope => config.scope
          ))
          throw(:warden)
        elsif params.include?('code')
          false and load_request_token_from_session
          if false and missing_stored_token?
            fail!("There is no OAuth2 authentication in progress")
          elsif false and !stored_token_match_recieved_token?
            fail!("Received OAuth2 token didn't match stored OAuth2 token")
          else
            user = find_user_by_access_token(access_token)
            if user.nil?
              fail!("User with access token not found")
              throw_error_with_oauth2_info
            else
              success!(user)
            end
          end
        end

      end

      def redirect_uri  
        uri = URI.parse(request.url)  
        uri.path = '/'  
        uri.query = nil  
        uri.to_s  
      end  

      def fail!(msg) #:nodoc:
        self.errors.add(service_param_name.to_sym, msg)
        super
      end
      
      ###################
      ### OAuth2 Logic ###
      ###################

      def client
        @client ||= ::OAuth2::Client.new(config.client_key, config.client_secret, config.options)
      end

      def request_token
        host_with_port = Warden::OAuth2::Utils.host_with_port(request)
        @request_token ||= client.get_request_token(:oauth_callback => host_with_port)
      end

      def access_token
        @access_token ||=
          # request_token.get_access_token(:oauth_verifier => params['oauth_verifier'])
          client.web_server.get_access_token(params[:code], :redirect_uri => redirect_uri)
      end

      protected

      def find_user_by_access_token(access_token)
        raise RuntimeError.new(<<-ERROR_MESSAGE) unless self.respond_to?(:_find_user_by_access_token)
        
You need to define a finder by access_token for this strategy.
Write on the warden initializer the following code:
Warden::OAuth2.access_token_user_finder(:#{config.provider_name}) do |access_token|
  # Logic to get your user from an access_token
end

ERROR_MESSAGE
        self._find_user_by_access_token(access_token)
      end

      def throw_error_with_oauth_info
        throw(:warden, :oauth2 => { 
          self.config.provider_name => {
            :provider => config.provider_name,
            :access_token => access_token,
            :client_key => config.client_key,
            :client_secret => config.client_secret
          }
        })
      end

      def store_request_token_on_session
        session[:request_token]  = request_token.token
        session[:request_secret] = request_token.secret
      end

      def load_request_token_from_session
        token  = session.delete(:request_token)
        secret = session.delete(:request_secret)
        @request_token = ::OAuth2::RequestToken.new(client, token, secret)
      end

      def missing_stored_token? 
        !request_token
      end

      def stored_token_match_recieved_token?
        request_token.token == params['code']
      end

      def service_param_name
        '%s_oauth2' % config.provider_name
      end

      def config
        self.class::CONFIG
      end

    end

  end
end
