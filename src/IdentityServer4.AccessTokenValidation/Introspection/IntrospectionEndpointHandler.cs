using IdentityModel.Client;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class IntrospectionEndpointHandler : AuthenticationHandler<IntrospectionEndpointOptions>
    {
        private const string BearerAuthSchema = "Bearer";
        private static readonly Lazy<HttpMessageHandler> _handler = new Lazy<HttpMessageHandler>(
            () => new HttpClientHandler(), isThreadSafe: true);

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            ValidateRequirements();

            // handle

            AuthenticateResult result;

            StringValues authorization;
            if (Request.Headers.TryGetValue("Authorization", out authorization) == false)
            {
                result = AuthenticateResult.Failed("No authorization header.");
            }
            else
            {
                if (authorization.ToString().StartsWith($"{BearerAuthSchema} ", StringComparison.OrdinalIgnoreCase) == false)
                {
                    return AuthenticateResult.Failed("Invalid or unsopported authentication schema.");
                }
                else
                {
                    var token = authorization.ToString().Substring($"{BearerAuthSchema} ".Length).Trim();
                    if (string.IsNullOrEmpty(token))
                    {
                        result = AuthenticateResult.Failed("No bearer token.");
                    }
                    else
                    {
                        result = await HandleImplAsync(token);
                    }
                }
            }

            return result;
        }

        private void ValidateRequirements()
        {
            if (string.IsNullOrWhiteSpace(Options.Authority))
            {
                throw new InvalidOperationException("Authority must be set to use validation endpoint.");
            }
        }

        private async Task<AuthenticateResult> HandleImplAsync(string token)
        {
            AuthenticateResult result;

            var cache = Context.RequestServices.GetService<IValidationResultCache>();
            if (cache != null)
            {
                var cachedClaims = await cache.GetAsync(token);
                if (cachedClaims != null)
                {
                    result = AuthenticateResult.Success(IssueTicket(cachedClaims));
                }
                else
                {
                    result = await HandleRemoteAsync(token, cache);
                }
            }
            else
            {
                result = await HandleRemoteAsync(token, null);
            }

            return result;
        }

        private async Task<AuthenticateResult> HandleRemoteAsync(string token, IValidationResultCache cache)
        {
            AuthenticateResult result;

            var introspectionEndpoint = $"{Options.Authority.EnsureTrailingSlash()}connect/introspect";
            var handler = Options.BackchannelHttpHandler ?? _handler.Value;
            IntrospectionClient introspectionClient = string.IsNullOrEmpty(Options.ScopeName) == false
                ? new IntrospectionClient(introspectionEndpoint, Options.ScopeName, Options.ScopeSecret ?? string.Empty, handler)
                : new IntrospectionClient(introspectionEndpoint, innerHttpMessageHandler: handler);

            IntrospectionResponse response;
            try
            {
                response = await introspectionClient.SendAsync(new IntrospectionRequest { Token = token });
            }
            catch (Exception ex)
            {
                Logger.LogError("Exception while contacting introspection endpoint", ex);
                return AuthenticateResult.Failed(ex);
            }

            if (response.IsError)
            {
                Logger.LogError("Error returned from introspection endpoint: {introspectionRequestError}", response.Error);
                result = AuthenticateResult.Failed(response.Error);
            }
            else if (!response.IsActive)
            {
                Logger.LogVerbose("Inactive token: {inactiveToken}", token);
                result = AuthenticateResult.Failed("Inactive token");
            }
            else
            {
                var claims = new List<Claim>();
                foreach (var claim in response.Claims)
                {
                    if (!string.Equals(claim.Item1, "active", StringComparison.Ordinal))
                    {
                        claims.Add(new Claim(claim.Item1, claim.Item2));
                    }
                }

                if (cache != null)
                {
                    await cache.AddAsync(token, claims, Options.ValidationResultCacheDuration);
                }

                result = AuthenticateResult.Success(IssueTicket(claims));
            }

            return result;
        }

        private AuthenticationTicket IssueTicket(IEnumerable<Claim> claims)
        {
            var identity = new ClaimsIdentity(claims, Options.AuthenticationScheme);

            return new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                Options.AuthenticationScheme);
        }
    }
}
