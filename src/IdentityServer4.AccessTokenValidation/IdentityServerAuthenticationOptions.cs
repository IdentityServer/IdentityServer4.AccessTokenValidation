using IdentityModel.AspNet.OAuth2Introspection;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using System;
using System.Collections.Generic;

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerAuthenticationOptions : AuthenticationOptions
    {
        public IdentityServerAuthenticationOptions()
        {
            AuthenticationScheme = "Bearer";
        }

        public string Authority { get; set; }

        public SupportedTokens SupportedTokens { get; set; } = SupportedTokens.Both;
        public Func<HttpRequest, string> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();

        public string ScopeName { get; set; }
        public string ScopeSecret { get; set; }
        public IEnumerable<string> AdditionalScopes { get; set; }

        public string NameClaimType { get; set; } = "name";
        public string RoleClaimType { get; set; } = "role";

        public bool SaveTokenAsClaim { get; set; } = true;
    }
}