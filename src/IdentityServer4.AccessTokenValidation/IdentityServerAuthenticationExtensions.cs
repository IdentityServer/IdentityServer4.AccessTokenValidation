// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.AspNetCore.Builder
{
    public static class IdentityServerAuthenticationExtensions
    {
        public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        {
            var combinedOptions = CombinedAuthenticationOptions.FromIdentityServerAuthenticationOptions(options);
            app.UseIdentityServerAuthentication(combinedOptions);

            return app.UseScopeValidation(options);
        }

        public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app, CombinedAuthenticationOptions options)
        {
            return app.UseMiddleware<IdentityServerAuthenticationMiddleware>(options);    
        }

        public static IApplicationBuilder UseScopeValidation(this IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        {
            if (options.ValidateScope)
            {
                var allowedScopes = new List<string>();
                if (!string.IsNullOrWhiteSpace(options.ScopeName))
                {
                    allowedScopes.Add(options.ScopeName);
                }

                if (options.AdditionalScopes != null && options.AdditionalScopes.Any())
                {
                    allowedScopes.AddRange(options.AdditionalScopes);
                }

                if (allowedScopes.Any())
                {
                    var scopeOptions = new ScopeValidationOptions
                    {
                        AllowedScopes = allowedScopes,
                        AuthenticationScheme = options.AuthenticationScheme
                    };

                    app.AllowScopes(scopeOptions);
                }
            }

            return app;
        }
    }
}