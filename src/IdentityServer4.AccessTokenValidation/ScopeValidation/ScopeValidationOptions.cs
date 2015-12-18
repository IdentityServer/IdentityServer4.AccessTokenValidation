using System.Collections.Generic;

namespace IdentityServer4.AccessTokenValidation
{
    public class ScopeValidationOptions
    {
        public IEnumerable<string> AllowedScopes { get; set; }
    }
}