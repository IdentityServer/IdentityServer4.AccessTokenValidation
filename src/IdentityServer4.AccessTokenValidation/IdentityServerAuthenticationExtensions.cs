// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation;
using Microsoft.Extensions.Logging;
using System.Linq;

namespace Microsoft.AspNetCore.Builder
{
    public static class IdentityServerAuthenticationExtensions
    {
        public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        {
            app.Validate(options);

            var combinedOptions = CombinedAuthenticationOptions.FromIdentityServerAuthenticationOptions(options);
            app.UseIdentityServerAuthentication(combinedOptions);

            return app;
        }

        public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app, CombinedAuthenticationOptions options)
        {
            app.UseMiddleware<IdentityServerAuthenticationMiddleware>(app, options);

            if (options.ScopeValidationOptions.AllowedScopes.Any())
            {
                app.AllowScopes(options.ScopeValidationOptions);
            }

            return app;
        }

        internal static void Validate(this IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        {
            var loggerFactory = app.ApplicationServices.GetService(typeof(ILoggerFactory)) as ILoggerFactory;
            if (loggerFactory == null) return;

            var logger = loggerFactory.CreateLogger("IdentityServer4.AccessTokenValidation.Startup");
            if (string.IsNullOrEmpty(options.ApiName) && !options.AllowedScopes.Any())
            {
                logger.LogInformation("Neither an ApiName nor allowed scopes are configured. It is recommended to configure some audience checking.");
            }
        }
    }
}
