// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    /// <summary>
    /// Authentication handler for validating both JWT and reference tokens
    /// </summary>
    public class IdentityServerAuthenticationHandler : AuthenticationHandler<IdentityServerAuthenticationOptions>
    {
        private readonly ILogger _logger;

        /// <inheritdoc />
        public IdentityServerAuthenticationHandler(
            IOptionsMonitor<IdentityServerAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            _logger = logger.CreateLogger<IdentityServerAuthenticationHandler>();
        }

        /// <summary>
        /// Tries to validate a token on the current request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            _logger.LogTrace("HandleAuthenticateAsync called");

            var token = Options.TokenRetriever(Context.Request);
            bool removeToken = false;

            try
            {
                if (token != null)
                {
                    _logger.LogTrace("Token found: {token}", token);
                    removeToken = true;

                    Context.Items.Add(IdentityServerAuthenticationDefaults.TokenItemsKey, token);

                    // seems to be a JWT
                    if (token.Contains('.') && Options.SupportsJwt)
                    {
                        _logger.LogTrace("Token is a JWT and is supported.");
                        return await Context.AuthenticateAsync(Scheme.Name + IdentityServerAuthenticationDefaults.JwtAuthenticationScheme);
                    }
                    else if (Options.SupportsIntrospection)
                    {
                        _logger.LogTrace("Token is a reference token and is supported.");
                        return await Context.AuthenticateAsync(Scheme.Name + IdentityServerAuthenticationDefaults.IntrospectionAuthenticationScheme);
                    }
                    else
                    {
                        _logger.LogTrace("Neither JWT nor reference tokens seem to be correctly configured for incoming token.");
                    }
                }

                return AuthenticateResult.NoResult();
            }
            finally
            {
                if (removeToken)
                {
                    Context.Items.Remove(IdentityServerAuthenticationDefaults.TokenItemsKey);
                }
            }
        }
    }
}