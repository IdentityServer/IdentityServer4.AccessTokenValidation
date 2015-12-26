using IdentityModel.Client;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.WebEncoders;
using System;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class OAuth2IntrospectionMiddleware : AuthenticationMiddleware<OAuth2IntrospectionOptions>
    {
        Lazy<IntrospectionClient> _client;

        public OAuth2IntrospectionMiddleware(RequestDelegate next, OAuth2IntrospectionOptions options, IUrlEncoder urlEncoder, ILoggerFactory loggerFactory)
            : base(next, options, loggerFactory, urlEncoder)
        {
            if (options.Authority.IsMissing() && options.IntrospectionEndpoint.IsMissing())
            {
                throw new InvalidOperationException("You must either set Authority or IntrospectionEndpoint");
            }

            if (options.ScopeName.IsMissing() && options.IntrospectionHttpHandler == null)
            {
                throw new InvalidOperationException("You must either set a ScopeName or set an introspection HTTP handler");
            }

            if (options.TokenRetriever == null)
            {
                throw new ArgumentException("TokenRetriever must be set", nameof(options.TokenRetriever));
            }

            _client = new Lazy<IntrospectionClient>(InitializeIntrospectionClient);
            if (options.DelayLoadDiscoveryDocument == false)
            {
                var temp = _client.Value;
            }
        }

        private IntrospectionClient InitializeIntrospectionClient()
        {
            string endpoint;

            if (Options.IntrospectionEndpoint.IsPresent())
            {
                endpoint = Options.IntrospectionEndpoint;
            }
            else
            {
                endpoint = GetIntrospectionEndpointFromDiscoveryDocument();
            }

            if (Options.IntrospectionHttpHandler != null)
            {
                return new IntrospectionClient(
                    endpoint,
                    innerHttpMessageHandler: Options.IntrospectionHttpHandler);
            }
            else
            {
                return new IntrospectionClient(endpoint);
            }
        }

        private string GetIntrospectionEndpointFromDiscoveryDocument()
        {
            // todo: use discovery document
            return Options.Authority.EnsureTrailingSlash() + "connect/introspect";
        }

        protected override AuthenticationHandler<OAuth2IntrospectionOptions> CreateHandler()
        {
            return new OAuth2IntrospectionHandler(_client.Value);
        }
    }
}