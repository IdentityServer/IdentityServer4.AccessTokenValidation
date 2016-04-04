using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.WebEncoders;
using System;
using System.Text.Encodings.Web;

namespace IdentityServer4.AccessTokenValidation.Infrastructure
{
    internal class NopAuthenticationMiddleware : AuthenticationMiddleware<NopAuthenticationOptions>
    {
        public NopAuthenticationMiddleware(RequestDelegate next, IOptions<NopAuthenticationOptions> options, ILoggerFactory loggerFactory, UrlEncoder encoder)
            : base(next, options, loggerFactory, encoder)
        {
            if (string.IsNullOrEmpty(Options.AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(Options.AuthenticationScheme));
            }
        }

        protected override AuthenticationHandler<NopAuthenticationOptions> CreateHandler()
        {
            return new NopAuthenticationHandler();
        }
    }
}