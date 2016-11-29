// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerAuthenticationMiddleware
    {
        private readonly ILogger<IdentityServerAuthenticationMiddleware> _logger;
        private readonly RequestDelegate _next;
        private readonly CombinedAuthenticationOptions _options;

        private readonly RequestDelegate _introspectionNext;
        private readonly RequestDelegate _jwtNext;
        private readonly RequestDelegate _nopNext;

        public IdentityServerAuthenticationMiddleware(RequestDelegate next, IApplicationBuilder app, CombinedAuthenticationOptions options, ILogger<IdentityServerAuthenticationMiddleware> logger)
        {
            _next = next;
            _options = options;
            _logger = logger;

            // building pipeline for introspection middleware
            if (options.IntrospectionOptions != null)
            {
                var introspectionBuilder = app.New();
                introspectionBuilder.UseOAuth2IntrospectionAuthentication(options.IntrospectionOptions);
                introspectionBuilder.Run(ctx => next(ctx));
                _introspectionNext = introspectionBuilder.Build();
            }

            // building pipeline for JWT bearer middleware
            if (options.JwtBearerOptions != null)
            {
                var jwtBuilder = app.New();
                jwtBuilder.UseJwtBearerAuthentication(options.JwtBearerOptions);
                jwtBuilder.Run(ctx => next(ctx));
                _jwtNext = jwtBuilder.Build();
            }

            // building pipeline for no token
            var nopBuilder = app.New();

            nopBuilder.UseMiddleware<NopAuthenticationMiddleware>(Options.Create(options.PassThruOptions));
            nopBuilder.Run(ctx => next(ctx));
            _nopNext = nopBuilder.Build();
        }

        public async Task Invoke(HttpContext context)
        {
            var token = _options.TokenRetriever(context.Request);

            if (token == null)
            {
                await _nopNext(context);
                return;
            }

            context.Items.Add("idsrv4:tokenvalidation:token", token);

            // seems to be a JWT
            if (token.Contains('.'))
            {
                // see if local validation is setup
                if (_jwtNext != null)
                {
                    await _jwtNext(context);
                    return;
                }
                // otherwise use introspection endpoint
                if (_introspectionNext != null)
                {
                    await _introspectionNext(context);
                    return;
                }

                _logger.LogWarning("No validator configured for JWT token");
            }
            else
            {
                // use introspection endpoint
                if (_introspectionNext != null)
                {
                    await _introspectionNext(context);
                    return;
                }

                _logger.LogWarning("No validator configured for reference token. Ensure ApiName and ApiSecret have been configured to use introspection.");
            }

            await _next(context);
        }
    }
}