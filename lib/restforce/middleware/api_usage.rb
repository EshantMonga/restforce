module Restforce
    class Middleware::APIUsage < Restforce::Middleware
        
        def call(env)
            api_usage(env[:response_headers])
            @app.call(env)
        end

        def api_usage(response)
            return nil unless response['sforce-limit-info']
            matches = response['sforce-limit-info'].match(%r{api-usage=(?<used>\d+)/(?<max>\d+)})
            if matches
                client.set_limits(matches['max'].to_i, matches['used'].to_i)
            end
        end
    end
end
