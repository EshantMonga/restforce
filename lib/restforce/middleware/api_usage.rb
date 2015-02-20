module Restforce
    class Middleware::APIUsage < Restforce::Middleware
        def call(env)
            api_usage(env[:response_headers])
            @app.call(env)
            #@app.call(env).on_complete do |env|
            #    api_usage(env[:response_headers])
            #end
        end

        def api_usage(response)
            return nil unless response['sforce-limit-info']
            matches = response['sforce-limit-info'].match(%r{api-usage=(?<used>\d+)/(?<max>\d+)})
            if matches
                @options[:max_api_requests] = matches['max'].to_i
                @options[:used_api_requests] = matches['used'].to_i
            end
        end
    end
end
