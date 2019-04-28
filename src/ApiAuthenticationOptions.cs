using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;

namespace IdentityServer4.AccessTokenValidation
{
    public class ApiAuthenticationOptions
    {
        public string Authority { get; set; }
        public string ApiName { get; set; }
        public SupportedTokens SupportedToken { get; set; } = SupportedTokens.Both;

        public Action<JwtBearerOptions> JwtBearerOptions { get; set; }
        public Action<OAuth2IntrospectionOptions> IntrospectionOptions { get; set; }

        public Func<HttpRequest, string> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();
    }
}