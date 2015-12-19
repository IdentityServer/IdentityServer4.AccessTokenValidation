using Microsoft.AspNet.Authentication;

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
    }
}