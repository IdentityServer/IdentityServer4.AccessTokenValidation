using System;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.DependencyInjection;
using IdentityServer4.AccessTokenValidation;

namespace MvcSample
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddAccessTokenValidationWithCaching();
        }

        public void Configure(IApplicationBuilder app)
        {
            var identityServerBearerTokenOptions = new IdentityServerBearerTokenOptions
            {
                Authority = "http://localhost:44300/",
                AutomaticAuthenticate = true,
                RequiredScopes = new[] { "read", "write" },
                PreserveAccessToken = true
            };

            var introceptionOptions = new IntrospectionEndpointOptions
            {
                ScopeName = "read",
                ScopeSecret = "secret",
                ValidationResultCacheDuration = TimeSpan.FromSeconds(30)
            };

            app.UseIdentityServerBearerTokenAuthentication(identityServerBearerTokenOptions, introceptionOptions);
            app.UseMvc();
        }
    }
}
