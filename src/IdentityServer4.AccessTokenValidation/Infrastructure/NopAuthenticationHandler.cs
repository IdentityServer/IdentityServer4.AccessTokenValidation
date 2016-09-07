// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation.Infrastructure
{
    internal class NopAuthenticationHandler : AuthenticationHandler<NopAuthenticationOptions>
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return Task.FromResult(AuthenticateResult.Fail("No token found."));
        }
    }
}