// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Authentication handler for validating both JWT and reference tokens
    /// </summary>
    public class IdentityServerAuthenticationHandler : AuthenticationHandler<IdentityServerAuthenticationOptions>
    {
        /// <inheritdoc />
        public IdentityServerAuthenticationHandler(
            IOptionsMonitor<IdentityServerAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

        /// <summary>
        /// Tries to validate a token on the current request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = Options.TokenRetriever(Context.Request);
            bool removeToken = false;

            try
            {
                if (token != null)
                {
                    removeToken = true;

                    Context.Items.Add(IdentityServerAuthenticationDefaults.TokenItemsKey, token);

                    // seems to be a JWT
                    if (token.Contains('.') && Options.SupportsJwt)
                    {
                        return await Context.AuthenticateAsync(Scheme.Name + IdentityServerAuthenticationDefaults.JwtAuthenticationScheme);
                    }
                    else if (Options.SupportsIntrospection)
                    {
                        return await Context.AuthenticateAsync(Scheme.Name + IdentityServerAuthenticationDefaults.IntrospectionAuthenticationScheme);
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