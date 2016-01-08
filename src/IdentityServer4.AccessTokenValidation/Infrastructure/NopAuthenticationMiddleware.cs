using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.WebEncoders;
using System;

namespace IdentityServer4.AccessTokenValidation.Infrastructure
{
    internal class NopAuthenticationMiddleware : AuthenticationMiddleware<NopAuthenticationOptions>
    {
        public NopAuthenticationMiddleware(RequestDelegate next, NopAuthenticationOptions options, ILoggerFactory loggerFactory, IUrlEncoder encoder)
            : base(next, options, loggerFactory, encoder)
        {
            if (string.IsNullOrEmpty(options.AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(options.AuthenticationScheme));
            }
        }

        protected override AuthenticationHandler<NopAuthenticationOptions> CreateHandler()
        {
            return new NopAuthenticationHandler();
        }
    }
}