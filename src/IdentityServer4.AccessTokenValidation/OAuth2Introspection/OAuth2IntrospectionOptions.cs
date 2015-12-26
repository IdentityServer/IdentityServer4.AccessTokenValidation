using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using System;
using System.Net.Http;

namespace IdentityServer4.AccessTokenValidation
{
    public class OAuth2IntrospectionOptions : AuthenticationOptions
    {
        public OAuth2IntrospectionOptions()
        {
            AuthenticationScheme = "Bearer";
        }

        // uses oidc disco and "introspection_endpoint"
        public string Authority { get; set; }

        public bool DelayLoadDiscoveryDocument { get; set; } = false;

        // explicitly set endpoint
        public string IntrospectionEndpoint { get; set; }

        public string ScopeName { get; set; }
        public string ScopeSecret { get; set; }

        public string NameClaimType { get; set; } = "name";
        public string RoleClaimType { get; set; } = "role";

        public TimeSpan DiscoveryTimeout { get; set; } = TimeSpan.FromSeconds(60);
        public HttpMessageHandler DiscoveryHttpHandler { get; set; }

        public TimeSpan IntrospectionTimeout { get; set; } = TimeSpan.FromSeconds(60);
        public HttpMessageHandler IntrospectionHttpHandler { get; set; }

        public bool SkipTokensWithDots { get; set; } = true;
        public bool SaveTokenAsClaim { get; set; } = true;
        public Func<HttpRequest, string> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();
    }
}