// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Microsoft.AspNetCore.Authorization
{
    public static class AuthorizationPolicyBuilderExtensions
    {
        public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder builder, params string[] scope)
        {
            return builder.RequireClaim("scope", scope);
        }
    }

    public static class ScopeAuthorizationPolicy
    {
        public static AuthorizationPolicy Create(params string[] scopes)
        {
            return new AuthorizationPolicyBuilder()
                .RequireScope(scopes)
                .Build();
        }
    }
}