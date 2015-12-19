using IdentityServer4.AccessTokenValidation;
using System;

namespace Microsoft.AspNet.Builder
{
    public static class IntrospectionAuthenticationApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseIntrospectionAuthentication(this IApplicationBuilder app, Action<IntrospectionAuthenticationOptions> configureOptions)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            var options = new IntrospectionAuthenticationOptions();
            if (configureOptions != null)
            {
                configureOptions(options);
            }

            return app.UseMiddleware<IntrospectionAuthenticationMiddleware>(options);
        }

        public static IApplicationBuilder UseIntrospectionAuthentication(this IApplicationBuilder app, IntrospectionAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<IntrospectionAuthenticationMiddleware>(options);
        }
    }
}