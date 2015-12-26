using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using System;
using System.Net.Http;

namespace IdentityServer4.AccessTokenValidation
{
    /// <summary>
    /// Options class for the OAuth 2.0 introspection endpoint authentication middleware
    /// </summary>
    public class OAuth2IntrospectionOptions : AuthenticationOptions
    {
        public OAuth2IntrospectionOptions()
        {
            AuthenticationScheme = "Bearer";
        }

        /// <summary>
        /// Sets the base-path of the token provider.
        /// If set, the OpenID Connect discovery document will be used to find the introspection endpoint.
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// Specifies if the discover document get loaded at startup time, or during the first request.
        /// </summary>
        public bool DelayLoadDiscoveryDocument { get; set; } = false;

        /// <summary>
        /// Sets the URL of the introspection endpoint.
        /// If set, Authority is ignored.
        /// </summary>
        public string IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Specifies the name of the introspection client.
        /// </summary>
        public string ScopeName { get; set; }

        /// <summary>
        /// Specifies the secret of the introspection client.
        /// </summary>
        public string ScopeSecret { get; set; }

        /// <summary>
        /// Specifies the claim type to use for the name claim (defaults to 'name')
        /// </summary>
        public string NameClaimType { get; set; } = "name";

        /// <summary>
        /// Specifies the claim type to use for the role claim (defaults to 'role')
        /// </summary>
        public string RoleClaimType { get; set; } = "role";

        /// <summary>
        /// Specifies the timout for contacting the discovery endpoint
        /// </summary>
        public TimeSpan DiscoveryTimeout { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Specifies the HTTP handler for the discovery endpoint
        /// </summary>
        public HttpMessageHandler DiscoveryHttpHandler { get; set; }

        /// <summary>
        /// Specifies the timeout for contacting the introspection endpoint
        /// </summary>
        public TimeSpan IntrospectionTimeout { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Specifies the HTTP handler for the introspection endpoint
        /// </summary>
        public HttpMessageHandler IntrospectionHttpHandler { get; set; }

        /// <summary>
        /// Specifies whether tokens that contain dots (most likely a JWT) are skipped
        /// </summary>
        public bool SkipTokensWithDots { get; set; } = true;

        /// <summary>
        /// Specifies whether the token should be added as claim called 'token' to the principal 
        /// </summary>
        public bool SaveTokenAsClaim { get; set; } = true;

        /// <summary>
        /// Specifies the method how to retrieve the token from the HTTP request
        /// </summary>
        public Func<HttpRequest, string> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();
    }
}