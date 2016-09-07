// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Text.Encodings.Web;

namespace IdentityServer4.AccessTokenValidation.Infrastructure
{
    internal class NopAuthenticationMiddleware : AuthenticationMiddleware<NopAuthenticationOptions>
    {
        public NopAuthenticationMiddleware(RequestDelegate next, IOptions<NopAuthenticationOptions> options, ILoggerFactory loggerFactory, UrlEncoder encoder)
            : base(next, options, loggerFactory, encoder)
        {
            if (string.IsNullOrEmpty(options.Value.AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(options.Value.AuthenticationScheme));
            }
        }

        protected override AuthenticationHandler<NopAuthenticationOptions> CreateHandler()
        {
            return new NopAuthenticationHandler();
        }
    }
}