module Warden
  module OAuth2

    #
    # Holds all the extensions made to Warden::Config in order to create OAuth2
    # consumers.
    #
    module ConfigExtension

      #
      # Helps to setup a new OAuth2 client authentication, to get started you need to define
      # a service name, and then on the block assign the different values required in order
      # to boot the OAuth2 process.
      # @param [Symbol] service An identifier of the OAuth2 service
      # 
      # @example
      #   use Warden::Manager do |config|
      #     config.oauth2(:twitter) do
      #       consumer_key "<YOUR CONSUMER KEY>"
      #       consumer_secret "<YOUR CONSUMER SECRET>"
      #       options :site => 'http://twitter.com'
      #     end
      #   end
      #
      def oauth2(service, &block)
        config = Warden::OAuth2::Config.new
        if block_given?
          if block.arity == 1 
            yield config 
          else
            config.instance_eval(&block)
          end
        end
        config.check_requirements
        config.provider_name = service
        Warden::OAuth2::Strategy.build(service, config)
      end
    
    end

  end
end

Warden::Config.send(:include, Warden::OAuth2::ConfigExtension)

