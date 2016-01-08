using Microsoft.AspNet.Authentication;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation.Infrastructure
{
    internal class NopAuthenticationHandler : AuthenticationHandler<NopAuthenticationOptions>
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return Task.FromResult(AuthenticateResult.Failed("No token found."));
        }
    }
}