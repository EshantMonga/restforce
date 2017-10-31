module Restforce
  # Faraday middleware that allows for on the fly authentication of requests.
  # When a request fails (a status of 401 is returned), the middleware
  # will attempt to either reauthenticate (username and password) or refresh
  # the oauth access token (if a refresh token is present).
  class Middleware::Authentication < Restforce::Middleware
    autoload :Password, 'restforce/middleware/authentication/password'
    autoload :Token,    'restforce/middleware/authentication/token'

    # Rescue from 401's, authenticate then raise the error again so the client
    # can reissue the request.
    def call(env)
      if @options[:token_provider].nil?
        begin
          @app.call(env)
        rescue Restforce::UnauthorizedError
          authenticate_with_no_token_provider!
          raise
        end
      else
        num_tries = 0
        while num_tries < 5
          begin
            return @app.call(env)
          rescue Restforce::UnauthorizedError
            authenticate_with_token_provider!
            num_tries += 1
          end
        end
      end
    end

    # Internal: Performs the authentication and returns the response body.
    def authenticate!
      if @options[:token_provider].nil?
        authenticate_with_no_token_provider!
      else
        authenticate_with_token_provider!
      end
    end

    # Internal: The params to post to the OAuth service.
    def params
      raise NotImplementedError
    end

    # Internal: Faraday connection to use when sending an authentication request.
    def connection
      @connection ||= Faraday.new(faraday_options) do |builder|
        builder.use Faraday::Request::UrlEncoded
        builder.use Restforce::Middleware::Mashify, nil, @options
        builder.response :json
        builder.use Restforce::Middleware::Logger, Restforce.configuration.logger, @options if Restforce.log?
        builder.adapter Faraday.default_adapter
      end
    end

    # Internal: The parsed error response.
    def error_message(response)
      "#{response.body['error']}: #{response.body['error_description']}"
    end

    # Featured detect form encoding.
    # URI in 1.8 does not include encode_www_form
    def encode_www_form(params)
      if URI.respond_to?(:encode_www_form)
        URI.encode_www_form(params)
      else
        params.map do |k, v|
          k, v = CGI.escape(k.to_s), CGI.escape(v.to_s)
          "#{k}=#{v}"
        end.join('&')
      end
    end

    private

    def authenticate_with_no_token_provider!
      response = connection.post '/services/oauth2/token' do |req|
        req.body = encode_www_form(params)
      end
      raise Restforce::AuthenticationError, error_message(response) if response.status != 200
      @options[:instance_url] = response.body['instance_url']
      @options[:oauth_token]  = response.body['access_token']
      @options[:authentication_callback].call(response.body) if @options[:authentication_callback]
      response.body
    end

    def authenticate_with_token_provider!
      refresh_access_token = -> {
        response = connection.post '/services/oauth2/token' do |req|
          req.body = encode_www_form(params)
        end
        raise Restforce::AuthenticationError, error_message(response) if response.status != 200
        response.body['access_token']
      }
      set_access_token = ->(access_token) { @options[:oauth_token] = access_token }

      token_provider = @options[:token_provider]
      token_provider.authenticate(
        @options[:oauth_token],
        refresh_access_token,
        set_access_token)
      { 'access_token': @options[:oauth_token] }
    end

    def faraday_options
      { :url   => "https://#{@options[:host]}",
        :proxy => @options[:proxy_uri] }.reject { |k, v| v.nil? }
    end
  end
end
