// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace IdentityServer4.AccessTokenValidation
{
    /// <summary>
    /// Supported token types
    /// </summary>
    public enum SupportedTokens
    {
        /// <summary>
        /// JWTs and reference tokens
        /// </summary>
        Both,

        /// <summary>
        /// JWTs only
        /// </summary>
        Jwt,

        /// <summary>
        /// Reference tokens only
        /// </summary>
        Reference
    }
}