using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.WebEncoders;

namespace IdentityServer4.AccessTokenValidation
{
    public class IntrospectionEndpointMiddleware : AuthenticationMiddleware<IntrospectionEndpointOptions>
    {
        public IntrospectionEndpointMiddleware(RequestDelegate next, IntrospectionEndpointOptions options, IUrlEncoder urlEncoder, ILoggerFactory loggerFactory)
            : base(next, options, loggerFactory, urlEncoder)
        {
        }

        protected override AuthenticationHandler<IntrospectionEndpointOptions> CreateHandler()
        {
            return new IntrospectionEndpointHandler();
        }
    }
}
