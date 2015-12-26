using IdentityModel.Client;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http.Authentication;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class OAuth2IntrospectionHandler : AuthenticationHandler<OAuth2IntrospectionOptions>
    {
        private readonly IntrospectionClient _client;

        public OAuth2IntrospectionHandler(IntrospectionClient client)
        {
            _client = client;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string token = Options.TokenRetriever(Context.Request);

            if (token.IsMissing())
            {
                return AuthenticateResult.Failed("No bearer token.");
            }

            if (token.Contains('.') && Options.SkipTokensWithDots)
            {
                return AuthenticateResult.Failed("Token contains a dot. Skipping.");
            }

            var response = await _client.SendAsync(new IntrospectionRequest
            {
                Token = token,
                ClientId = Options.ScopeName,
                ClientSecret = Options.ScopeSecret
            });

            if (response.IsError)
            {
                return AuthenticateResult.Failed("Error returned from introspection: " + response.Error);
            }

            if (response.IsActive)
            {
                var claims = new List<Claim>(response.Claims
                    .Where(c => c.Item1 != "active")
                    .Select(c => new Claim(c.Item1, c.Item2)));

                if (Options.SaveTokenAsClaim)
                {
                    claims.Add(new Claim("token", token));
                }

                var id = new ClaimsIdentity(claims, Options.AuthenticationScheme, Options.NameClaimType, Options.RoleClaimType);
                var principal = new ClaimsPrincipal(id);

                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Failed("invalid token.");
        }
    }
}