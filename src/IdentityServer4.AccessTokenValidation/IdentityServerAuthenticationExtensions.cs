// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation;
using System.Linq;

namespace Microsoft.AspNetCore.Builder
{
    public static class IdentityServerAuthenticationExtensions
    {
        public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        {
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
    }
}
