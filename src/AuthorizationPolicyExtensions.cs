// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;

namespace Microsoft.AspNetCore.Authorization
{
    /// <summary>
    /// Extensions for creating scope related authorization policies
    /// </summary>
    public static class AuthorizationPolicyBuilderExtensions
    {
        /// <summary>
        /// Adds a policy to check for required scopes.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="scope">List of any required scopes. The token must contain at least one of the listed scopes.</param>
        /// <returns></returns>
        public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder builder, params string[] scope)
        {
            return builder.RequireClaim(JwtClaimTypes.Scope, scope);
        }
    }

    /// <summary>
    /// Helper for creating scope-related policies
    /// </summary>
    public static class ScopePolicy
    {
        /// <summary>
        /// Creates a policy to check for required scopes.
        /// </summary>
        /// <param name="scopes">List of any required scopes. The token must contain at least one of the listed scopes.</param>
        /// <returns></returns>
        public static AuthorizationPolicy Create(params string[] scopes)
        {
            return new AuthorizationPolicyBuilder()
                .RequireScope(scopes)
                .Build();
        }
    }
}