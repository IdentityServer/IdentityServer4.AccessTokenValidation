using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using System;

namespace IdentityServer4.AccessTokenValidation
{
    public class IntrospectionAuthenticationOptions : AuthenticationOptions
    {
        public IntrospectionAuthenticationOptions()
        {
            AuthenticationScheme = "Bearer";
        }

        public string Authority { get; set; }
        public string ScopeName { get; set; }
        public string ScopeSecret { get; set; }

        public bool SkipTokensWithDots { get; set; } = true;
        public bool PreserveAccessToken { get; set; } = true;
        public Func<HttpRequest, string> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();
    }
}