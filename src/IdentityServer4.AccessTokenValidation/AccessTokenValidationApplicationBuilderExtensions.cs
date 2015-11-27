using IdentityServer4.AccessTokenValidation;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.AspNet.Builder
{
    public static class AccessTokenValidationApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseIdentityServerBearerTokenAuthentication(this IApplicationBuilder app, IdentityServerBearerTokenOptions options)
        {
            return UseIdentityServerBearerTokenAuthentication(app, options, null);
        }

        public static IApplicationBuilder UseIdentityServerBearerTokenAuthentication(this IApplicationBuilder app, IdentityServerBearerTokenOptions options, IntrospectionEndpointOptions introspectionEndpointOptions)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (introspectionEndpointOptions != null)
            {
                var alignedIntrospectionEndpointOptions = AlignIntrospectionEndpointOptions(options, introspectionEndpointOptions);
                app.UseIntrospectionEndpointAuthentication(alignedIntrospectionEndpointOptions);
            }
            else
            {
                app.UseJwtBearerAuthentication(options);
            }

            if (options.RequiredScopes.Any())
            {
                IEnumerable<string> scopes = options.RequiredScopes.Concat(new[] { introspectionEndpointOptions.ScopeName });
                app.UseMiddleware<ScopeRequirementMiddleware>(scopes);
            }

            return app;
        }

        private static IntrospectionEndpointOptions AlignIntrospectionEndpointOptions(IdentityServerBearerTokenOptions options, IntrospectionEndpointOptions introspectionEndpointOptions)
        {
            introspectionEndpointOptions.Authority = introspectionEndpointOptions.Authority ?? options.Authority;
            introspectionEndpointOptions.AutomaticAuthenticate = introspectionEndpointOptions.AutomaticAuthenticate || options.AutomaticAuthenticate;
            introspectionEndpointOptions.AutomaticChallenge = introspectionEndpointOptions.AutomaticChallenge || options.AutomaticChallenge;
            introspectionEndpointOptions.ClaimsIssuer = introspectionEndpointOptions.ClaimsIssuer ?? options.ClaimsIssuer;
            introspectionEndpointOptions.PreserveAccessToken = introspectionEndpointOptions.PreserveAccessToken || options.PreserveAccessToken;

            return introspectionEndpointOptions;
        }

        private static IApplicationBuilder UseIntrospectionEndpointAuthentication(this IApplicationBuilder app, IntrospectionEndpointOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            app.UseMiddleware<IntrospectionEndpointMiddleware>(options);

            return app;
        }
    }
}
