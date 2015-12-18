using Microsoft.AspNet.Authentication;

namespace IdentityServer4.AccessTokenValidation
{
    public class IntrospectionEndpointOptions : AuthenticationOptions
    {
        public IntrospectionEndpointOptions()
        {
            AuthenticationScheme = "Bearer";
        }

        public string Authority { get; set; }
        public string ScopeName { get; set; }
        public string ScopeSecret { get; set; }
    }
}