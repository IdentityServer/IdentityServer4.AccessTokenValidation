using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;

namespace IdentityServer4.AccessTokenValidation
{
    public class CombinedAuthenticationOptions
    {
        public string AuthenticationScheme { get; set; }
        public Func<HttpRequest, string> TokenRetriever { get; set; }

        public OAuth2IntrospectionOptions IntrospectionOptions { get; set; }
        public JwtBearerOptions JwtBearerOptions { get; set; }
    }
}