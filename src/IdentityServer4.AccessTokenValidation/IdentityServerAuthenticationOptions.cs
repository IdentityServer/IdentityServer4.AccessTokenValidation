using IdentityModel.AspNet.OAuth2Introspection;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerAuthenticationOptions : AuthenticationOptions
    {
        public IdentityServerAuthenticationOptions()
        {
            AuthenticationScheme = "Bearer";
            AdditionalScopes = Enumerable.Empty<string>();
        }

        public string Authority { get; set; }

        public SupportedTokens SupportedTokens { get; set; } = SupportedTokens.Both;
        public Func<HttpRequest, string> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();

        public string ScopeName { get; set; }
        public string ScopeSecret { get; set; }
        public IEnumerable<string> AdditionalScopes { get; set; }

        public string NameClaimType { get; set; } = "name";
        public string RoleClaimType { get; set; } = "role";

        public bool SaveTokensAsClaim { get; set; } = false;

        public HttpMessageHandler JwtBackChannelHandler { get; set; }
        public HttpMessageHandler IntrospectionBackChannelHandler { get; set; }
        public HttpMessageHandler IntrospectionDiscoveryHandler { get; set; }
        public TimeSpan BackChannelTimeouts { get; set; } = TimeSpan.FromSeconds(60);
    }
}