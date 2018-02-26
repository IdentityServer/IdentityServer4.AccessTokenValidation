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
                    var effectiveScheme = default(string);

                    Context.Items.Add(IdentityServerAuthenticationDefaults.TokenItemsKey, token);

                    // seems to be a JWT
                    if (token.Contains('.') && Options.SupportsJwt)
                    {
                        _logger.LogTrace("Token is a JWT and is supported.");
                        effectiveScheme = Scheme.Name + IdentityServerAuthenticationDefaults.JwtAuthenticationScheme;
                        
                        return await Context.AuthenticateAsync(effectiveScheme);
                    }
                    else if (Options.SupportsIntrospection)
                    {
                        _logger.LogTrace("Token is a reference token and is supported.");
                        effectiveScheme = Scheme.Name + IdentityServerAuthenticationDefaults.IntrospectionAuthenticationScheme;

                        return await Context.AuthenticateAsync(effectiveScheme);
                    }
                    else
                    {
                        _logger.LogTrace("Neither JWT nor reference tokens seem to be correctly configured for incoming token.");
                    }

                    if (!string.IsNullOrWhiteSpace(effectiveScheme))
                    {
                        Context.Items.Add(IdentityServerAuthenticationDefaults.EffectiveSchemeKey + Scheme.Name, effectiveScheme);
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

        /// <summary>
        /// Override this method to deal with 401 challenge concerns, if an authentication scheme in question
        /// deals an authentication interaction as part of it's request flow. (like adding a response header, or
        /// changing the 401 result to 302 of a login page or external sign-in location.)
        /// </summary>
        /// <param name="properties"></param>
        /// <returns>
        /// A Task.
        /// </returns>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (Context.Items.TryGetValue(IdentityServerAuthenticationDefaults.EffectiveSchemeKey + Scheme.Name, out object value))
            {
                if (value is string scheme)
                {
                    _logger.LogTrace("Forwarding challenge to scheme: {scheme}", scheme);
                    await Context.ChallengeAsync(scheme);
                }
            }
            else
            {
                await base.HandleChallengeAsync(properties);
            }
        }
    }
}