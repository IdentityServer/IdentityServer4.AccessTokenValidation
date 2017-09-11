// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerAuthenticationDefaults
    {
        public const string AuthenticationScheme = "Bearer";

        public const string IntrospectionAuthenticationScheme = "IdentityServerAuthenticationIntrospection";
        public const string JwtAuthenticationScheme = "IdentityServerAuthenticationJwt";
        public const string TokenItemsKey = "idsrv4:tokenvalidation:token";
    }
}