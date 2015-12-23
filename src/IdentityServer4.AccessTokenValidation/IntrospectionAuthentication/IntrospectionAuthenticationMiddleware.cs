using IdentityModel.Client;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.WebEncoders;
using System;

namespace IdentityServer4.AccessTokenValidation
{
    public class IntrospectionAuthenticationMiddleware : AuthenticationMiddleware<IntrospectionAuthenticationOptions>
    {
        IntrospectionClient _client;

        public IntrospectionAuthenticationMiddleware(RequestDelegate next, IntrospectionAuthenticationOptions options, IUrlEncoder urlEncoder, ILoggerFactory loggerFactory)
            : base(next, options, loggerFactory, urlEncoder)
        {
            if (options.Authority.IsMissing())
            {
                throw new ArgumentException("Authority must be set", nameof(options.Authority));
            }

            if (options.TokenRetriever == null)
            {
                throw new ArgumentException("TokenRetriever must be set", nameof(options.TokenRetriever));
            }

            if (options.ScopeName.IsMissing())
            {
                throw new ArgumentException("Scope name must be set", nameof(options.ScopeName));
            }

            _client = new IntrospectionClient(
                options.Authority.EnsureTrailingSlash() + "connect/introspect",
                options.ScopeName,
                options.ScopeSecret);
        }

        protected override AuthenticationHandler<IntrospectionAuthenticationOptions> CreateHandler()
        {
            return new IntrospectionAuthenticationHandler(_client);
        }
    }
}