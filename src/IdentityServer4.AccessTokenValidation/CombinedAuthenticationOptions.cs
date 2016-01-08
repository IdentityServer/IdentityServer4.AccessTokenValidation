using IdentityModel.AspNet.OAuth2Introspection;
using Microsoft.AspNet.Authentication.JwtBearer;
using Microsoft.AspNet.Http;
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