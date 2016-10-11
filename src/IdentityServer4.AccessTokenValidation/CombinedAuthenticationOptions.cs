// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace IdentityServer4.AccessTokenValidation
{
    public class CombinedAuthenticationOptions
    {
        static Func<HttpRequest, string> _tokenRetriever = request => request.HttpContext.Items["idsrv4:tokenvalidation:token"] as string;

        public string AuthenticationScheme { get; set; }
        public Func<HttpRequest, string> TokenRetriever { get; set; }

        public OAuth2IntrospectionOptions IntrospectionOptions { get; set; }
        public JwtBearerOptions JwtBearerOptions { get; set; }
        public ScopeValidationOptions ScopeValidationOptions { get; set; }

        public static CombinedAuthenticationOptions FromIdentityServerAuthenticationOptions(IdentityServerAuthenticationOptions options)
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

                    combinedOptions.ScopeValidationOptions = scopeOptions;
                }
                else
                {
                    var scopeOptions = new ScopeValidationOptions
                    {
                        AllowedScopes = new string[] { }
                    };

                    combinedOptions.ScopeValidationOptions = scopeOptions;
                }
            }

            return combinedOptions;
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
                        return options.JwtBearerEvents.MessageReceived(e);
                    },
                    OnTokenValidated = e => options.JwtBearerEvents.TokenValidated(e),
                    OnAuthenticationFailed = e => options.JwtBearerEvents.AuthenticationFailed(e),
                    OnChallenge = e => options.JwtBearerEvents.Challenge(e)
                }
            };

            if (options.JwtBackChannelHandler != null)
            {
                jwtOptions.BackchannelHttpHandler = options.JwtBackChannelHandler;
            }

            jwtOptions.TokenValidationParameters.ValidateAudience = false;
            jwtOptions.TokenValidationParameters.NameClaimType = options.NameClaimType;
            jwtOptions.TokenValidationParameters.RoleClaimType = options.RoleClaimType;

            if (options.InboundJwtClaimTypeMap != null)
            {
                var handler = new JwtSecurityTokenHandler();
                handler.InboundClaimTypeMap = options.InboundJwtClaimTypeMap;

                jwtOptions.SecurityTokenValidators.Clear();
                jwtOptions.SecurityTokenValidators.Add(handler);
            }

            return jwtOptions;
        }
    }
}