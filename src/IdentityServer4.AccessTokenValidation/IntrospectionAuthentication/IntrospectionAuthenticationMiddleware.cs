using IdentityModel.Client;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.WebEncoders;

namespace IdentityServer4.AccessTokenValidation
{
    public class IntrospectionAuthenticationMiddleware : AuthenticationMiddleware<IntrospectionAuthenticationOptions>
    {
        IntrospectionClient _client;

        public IntrospectionAuthenticationMiddleware(RequestDelegate next, IntrospectionAuthenticationOptions options, IUrlEncoder urlEncoder, ILoggerFactory loggerFactory)
            : base(next, options, loggerFactory, urlEncoder)
        {
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