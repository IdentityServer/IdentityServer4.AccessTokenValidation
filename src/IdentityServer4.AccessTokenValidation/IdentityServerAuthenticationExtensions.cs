﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Extensions for registering the IdentityServer authentication handler
    /// </summary>
    public static class IdentityServerAuthenticationExtensions
    {
        /// <summary>
        /// Registers the IdentityServer authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder)
            => builder.AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme);

        /// <summary>
        /// Registers the IdentityServer authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder, string authenticationScheme)
            => builder.AddIdentityServerAuthentication(authenticationScheme, configureOptions: null);

        /// <summary>
        /// Registers the IdentityServer authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <param name="jwtBearerConfigureOptions">The JWT Bearer configure options.</param>
        /// <param name="oAuth2IntrospectionConfigureOptions">The OAuth2 Introspection configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder,
            Action<IdentityServerAuthenticationOptions> configureOptions, Action<JwtBearerOptions> jwtBearerConfigureOptions = null,
            Action<OAuth2IntrospectionOptions> oAuth2IntrospectionConfigureOptions = null) =>
            builder.AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme, configureOptions,
                jwtBearerConfigureOptions, oAuth2IntrospectionConfigureOptions);

        /// <summary>
        /// Registers the IdentityServer authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <param name="jwtBearerConfigureOptions">The JWT Bearer configure options.</param>
        /// <param name="oAuth2IntrospectionConfigureOptions">The OAuth2 Introspection configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder, string authenticationScheme,
            Action<IdentityServerAuthenticationOptions> configureOptions, Action<JwtBearerOptions> jwtBearerConfigureOptions = null,
            Action<OAuth2IntrospectionOptions> oAuth2IntrospectionConfigureOptions = null)
        {
            builder.AddJwtBearer(authenticationScheme + IdentityServerAuthenticationDefaults.JwtAuthenticationScheme, jwtBearerConfigureOptions);
            builder.AddOAuth2Introspection(authenticationScheme + IdentityServerAuthenticationDefaults.IntrospectionAuthenticationScheme, oAuth2IntrospectionConfigureOptions);

            builder.Services.AddSingleton<IConfigureOptions<JwtBearerOptions>>(services =>
            {
                var monitor = services.GetRequiredService<IOptionsMonitor<IdentityServerAuthenticationOptions>>();
                return new ConfigureInternalOptions(monitor.Get(authenticationScheme), authenticationScheme);
            });

            builder.Services.AddSingleton<IConfigureOptions<OAuth2IntrospectionOptions>>(services =>
            {
                var monitor = services.GetRequiredService<IOptionsMonitor<IdentityServerAuthenticationOptions>>();
                return new ConfigureInternalOptions(monitor.Get(authenticationScheme), authenticationScheme);
            });

            return builder.AddScheme<IdentityServerAuthenticationOptions, IdentityServerAuthenticationHandler>(authenticationScheme,
                configureOptions);
        }

        /// <summary>
        /// Registers the IdentityServer authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="jwtBearerOptions">The JWT bearer options.</param>
        /// <param name="introspectionOptions">The introspection options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder, string authenticationScheme, 
            Action<JwtBearerOptions> jwtBearerOptions,
            Action<OAuth2IntrospectionOptions> introspectionOptions)
        {
            if (jwtBearerOptions != null)
            {
                builder.AddJwtBearer(authenticationScheme + IdentityServerAuthenticationDefaults.JwtAuthenticationScheme, jwtBearerOptions);
            }

            if (introspectionOptions != null)
            {
                builder.AddOAuth2Introspection(authenticationScheme + IdentityServerAuthenticationDefaults.IntrospectionAuthenticationScheme, introspectionOptions);
            }

            return builder.AddScheme<IdentityServerAuthenticationOptions, IdentityServerAuthenticationHandler>(authenticationScheme, (o) => { });
        }
    }
}