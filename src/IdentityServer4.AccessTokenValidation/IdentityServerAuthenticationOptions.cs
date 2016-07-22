// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.AspNetCore.OAuth2Introspection;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace Microsoft.AspNetCore.Builder
{
    public class IdentityServerAuthenticationOptions : AuthenticationOptions
    {
        public IdentityServerAuthenticationOptions()
        {
            AuthenticationScheme = "Bearer";
        }

        /// <summary>
        /// Base-address of the token issuer
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// Specifies whether HTTPS is required for the discovery endpoint
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;
        
        /// <summary>
        /// Specifies which token types are supported (JWT, reference or both)
        /// </summary>
        public SupportedTokens SupportedTokens { get; set; } = SupportedTokens.Both;

        /// <summary>
        /// Callback to retrieve token from incoming request
        /// </summary>
        public Func<HttpRequest, string> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();

        /// <summary>
        /// Name of the scope used for scope validation and for authentication against introspection endpoint
        /// </summary>
        public string ScopeName { get; set; }

        /// <summary>
        /// Secret used for authentication against introspection endpoint
        /// </summary>
        public string ScopeSecret { get; set; }

        /// <summary>
        /// Additional scope names used for validation
        /// </summary>
        public IEnumerable<string> AdditionalScopes { get; set; } = Enumerable.Empty<string>();

        /// <summary>
        /// Specifies whether the scopes should be validated or not
        /// </summary>
        public bool ValidateScope { get; set; } = true;

        /// <summary>
        /// Claim type for name
        /// </summary>
        public string NameClaimType { get; set; } = "name";

        /// <summary>
        /// Claim type for role
        /// </summary>
        public string RoleClaimType { get; set; } = "role";

        /// <summary>
        /// Specifies inbound claim type map for JWT tokens (mainly used to disable the annoying default behavior of the MS JWT handler)
        /// </summary>
        public Dictionary<string, string> InboundJwtClaimTypeMap { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Specifies whether caching is enabled for introspection responses (requires a distributed cache implementation)
        /// </summary>
        public bool EnableCaching { get; set; } = false;

        /// <summary>
        /// Specifies ttl for introspection response caches
        /// </summary>
        public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// specifies whether the token should be saved in the authentication properties
        /// </summary>
        public bool SaveToken { get; set; } = true;

        /// <summary>
        /// back-channel handler for JWT middleware
        /// </summary>
        public HttpMessageHandler JwtBackChannelHandler { get; set; }

        /// <summary>
        /// back-channel handler for introspection endpoint
        /// </summary>
        public HttpMessageHandler IntrospectionBackChannelHandler { get; set; }

        /// <summary>
        /// back-channel handler for introspection discovery endpoint
        /// </summary>
        public HttpMessageHandler IntrospectionDiscoveryHandler { get; set; }

        /// <summary>
        /// timeout for back-channel operations
        /// </summary>
        public TimeSpan BackChannelTimeouts { get; set; } = TimeSpan.FromSeconds(60);
    }
}