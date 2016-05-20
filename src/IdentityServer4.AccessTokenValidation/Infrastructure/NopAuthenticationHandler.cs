using Microsoft.AspNetCore.Authentication;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation.Infrastructure
{
    internal class NopAuthenticationHandler : AuthenticationHandler<NopAuthenticationOptions>
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return Task.FromResult(AuthenticateResult.Fail("No token found."));
        }
    }
}