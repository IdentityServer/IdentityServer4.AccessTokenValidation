using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Text.Encodings.Web;

namespace IdentityServer4.AccessTokenValidation.Infrastructure
{
    internal class NopAuthenticationMiddleware : AuthenticationMiddleware<NopAuthenticationOptions>
    {
        public NopAuthenticationMiddleware(RequestDelegate next, IOptions<NopAuthenticationOptions> options, ILoggerFactory loggerFactory, UrlEncoder encoder)
            : base(next, options, loggerFactory, encoder)
        {
            if (string.IsNullOrEmpty(options.Value.AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(options.Value.AuthenticationScheme));
            }
        }
        
        protected override AuthenticationHandler<NopAuthenticationOptions> CreateHandler()
        {
            return new NopAuthenticationHandler();
        }
    }
}