// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using System.Threading.Tasks;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Tests.Util
{
    class PipelineFactory
    {
        public static TestServer CreateServer(Action<IdentityServerAuthenticationOptions> options)
        {
            return new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services
                        .AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
                        .AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme, options);
                })
                .Configure(app =>
                {
                    app.UseAuthentication();

                    app.Use((context, next) =>
                    {
                        var user = context.User;

                        if (user.Identity.IsAuthenticated)
                        {
                            context.Response.StatusCode = 200;
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                        }

                        return Task.CompletedTask;
                    });
                }));
        }

        public static TestServer CreateServer2()
        {
            return new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services
                        .AddApiAuthentication("api", options =>
                        {
                            options.Authority = "https://foo.com";
                            options.ApiName = "api1";
                        });
                })
                .Configure(app =>
                {
                    app.UseAuthentication();

                    app.Use((context, next) =>
                    {
                        var user = context.User;

                        if (user.Identity.IsAuthenticated)
                        {
                            context.Response.StatusCode = 200;
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                        }

                        return Task.CompletedTask;
                    });
                }));
        }

        public static HttpClient CreateClient2()
        {
            return CreateServer2().CreateClient();
        }

        public static HttpClient CreateClient(Action<IdentityServerAuthenticationOptions> options)
        {
            return CreateServer(options).CreateClient();
        }

        public static HttpMessageHandler CreateHandler(Action<IdentityServerAuthenticationOptions> options)
        {
            return CreateServer(options).CreateHandler();
        }
    }
}