using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerAuthenticationMiddleware
    {
        private readonly ILogger<IdentityServerAuthenticationMiddleware> _logger;
        private readonly RequestDelegate _next;
        private readonly CombinedAuthenticationOptions _options;

        private readonly RequestDelegate _introspectionNext;
        private readonly RequestDelegate _jwtNext;

        public IdentityServerAuthenticationMiddleware(RequestDelegate next, IApplicationBuilder app, CombinedAuthenticationOptions options, ILogger<IdentityServerAuthenticationMiddleware> logger)
        {
            _next = next;
            _options = options;
            _logger = logger;

            if (options.IntrospectionOptions != null)
            {
                var introspectionBuilder = app.New();
                introspectionBuilder.UseOAuth2IntrospectionAuthentication(options.IntrospectionOptions);
                introspectionBuilder.Run(ctx => next(ctx));
                _introspectionNext = introspectionBuilder.Build();
            }

            if (options.JwtBearerOptions != null)
            {
                var jwtBuilder = app.New();
                jwtBuilder.UseJwtBearerAuthentication(options.JwtBearerOptions);
                jwtBuilder.Run(ctx => next(ctx));
                _jwtNext = jwtBuilder.Build();
            }
        }

        public async Task Invoke(HttpContext context)
        {
            var token = _options.TokenRetriever(context.Request);

            if (token == null)
            {
                await _next(context);
                return;
            }

            context.Items.Add("idsrv4:tokenvalidation:token", token);

            // seems to be a JWT
            if (token.Contains('.'))
            {
                // see if local validation is setup
                if (_jwtNext != null)
                {
                    await _jwtNext(context);
                    return;
                }
                // otherwise use validation endpoint
                if (_introspectionNext != null)
                {
                    await _introspectionNext(context);
                    return;
                }

                _logger.LogWarning("No validator configured for JWT token");
            }
            else
            {
                // use validation endpoint
                if (_introspectionNext != null)
                {
                    await _introspectionNext(context);
                    return;
                }

                _logger.LogWarning("No validator configured for reference token");
            }

            await _next(context);
        }
    }
}