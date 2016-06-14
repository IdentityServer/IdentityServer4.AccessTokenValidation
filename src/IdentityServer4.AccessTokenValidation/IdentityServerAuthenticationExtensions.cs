// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Builder
{
    public static class IdentityServerAuthenticationExtensions
    {
        static Func<HttpRequest, string> _tokenRetriever = request => request.HttpContext.Items["idsrv4:tokenvalidation:token"] as string;

        public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        {
            var combinedOptions = new CombinedAuthenticationOptions();
            combinedOptions.TokenRetriever = options.TokenRetriever;
            combinedOptions.AuthenticationScheme = options.AuthenticationScheme;
            
            switch (options.SupportedTokens)
            {
                case SupportedTokens.Jwt:
                    combinedOptions.JwtBearerOptions = ConfigureJwt(options);
                    break;
                case SupportedTokens.Reference:
                    combinedOptions.IntrospectionOptions = ConfigureIntrospection(options);
                    break;
                case SupportedTokens.Both:
                    combinedOptions.JwtBearerOptions = ConfigureJwt(options);
                    combinedOptions.IntrospectionOptions = ConfigureIntrospection(options);
                    break;
                default:
                    throw new Exception("SupportedTokens has invalid value");
            }

            app.UseMiddleware<IdentityServerAuthenticationMiddleware>(app, combinedOptions);

            if (options.ValidateScope)
            {
                var allowedScopes = new List<string>();
                if (!string.IsNullOrWhiteSpace(options.ScopeName))
                {
                    allowedScopes.Add(options.ScopeName);
                }

                if (options.AdditionalScopes != null && options.AdditionalScopes.Any())
                {
                    allowedScopes.AddRange(options.AdditionalScopes);
                }

                if (allowedScopes.Any())
                {
                    var scopeOptions = new ScopeValidationOptions
                    {
                        AllowedScopes = allowedScopes,
                        AuthenticationScheme = options.AuthenticationScheme
                    };

                    app.AllowScopes(scopeOptions);
                }
            }

            return app;
        }

        private static OAuth2IntrospectionOptions ConfigureIntrospection(IdentityServerAuthenticationOptions options)
        {
            var introspectionOptions = new OAuth2IntrospectionOptions
            {
                AuthenticationScheme = options.AuthenticationScheme,
                Authority = options.Authority,
                ScopeName = options.ScopeName,
                ScopeSecret = options.ScopeSecret,

                AutomaticAuthenticate = options.AutomaticAuthenticate,
                AutomaticChallenge = options.AutomaticChallenge,

                NameClaimType = options.NameClaimType,
                RoleClaimType = options.RoleClaimType,

                TokenRetriever = _tokenRetriever,
                SaveToken = options.SaveToken,

                EnableCaching = options.EnableCaching,
                CacheDuration = options.CacheDuration,

                DiscoveryTimeout = options.BackChannelTimeouts,
                IntrospectionTimeout = options.BackChannelTimeouts
            };

            if (options.IntrospectionBackChannelHandler != null)
            {
                introspectionOptions.IntrospectionHttpHandler = options.IntrospectionBackChannelHandler;
            }
            if (options.IntrospectionDiscoveryHandler != null)
            {
                introspectionOptions.DiscoveryHttpHandler = options.IntrospectionDiscoveryHandler;
            }

            return introspectionOptions;
        }

        private static JwtBearerOptions ConfigureJwt(IdentityServerAuthenticationOptions options)
        {
            var jwtOptions = new JwtBearerOptions
            {
                AuthenticationScheme = options.AuthenticationScheme,
                Authority = options.Authority,
                RequireHttpsMetadata = options.RequireHttpsMetadata,

                AutomaticAuthenticate = options.AutomaticAuthenticate,
                AutomaticChallenge = options.AutomaticChallenge,

                BackchannelTimeout = options.BackChannelTimeouts,
                RefreshOnIssuerKeyNotFound = true,

                SaveToken = options.SaveToken,

                Events = new JwtBearerEvents
                {
                    OnMessageReceived = e =>
                    {
                        e.Token = _tokenRetriever(e.Request);

                        return Task.FromResult(0);
                    },
                }
            };

            if (options.JwtBackChannelHandler != null)
            {
                jwtOptions.BackchannelHttpHandler = options.JwtBackChannelHandler;
            }

            jwtOptions.TokenValidationParameters.ValidateAudience = false;
            jwtOptions.TokenValidationParameters.NameClaimType = options.NameClaimType;
            jwtOptions.TokenValidationParameters.RoleClaimType = options.RoleClaimType;
            
            return jwtOptions;
        }
    }
}