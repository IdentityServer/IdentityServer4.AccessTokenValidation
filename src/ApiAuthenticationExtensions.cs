using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityServer4.AccessTokenValidation
{
    public static class ApiAuthenticationExtensions
    {
        public static IServiceCollection AddApiAuthentication(this IServiceCollection services, string scheme, Action<ApiAuthenticationOptions> options)
        {
            ApiAuthenticationOptions apiOptions = new ApiAuthenticationOptions();
            options(apiOptions);

            Action<JwtBearerOptions> jwtOptions = o =>
            {
                o.Authority = apiOptions.Authority;
                o.Audience = apiOptions.ApiName;

                apiOptions.JwtBearerOptions(o);
            };

            Action<OAuth2IntrospectionOptions> intospectionOptions = o =>
            {
                o.Authority = apiOptions.Authority;
                o.ClientId = apiOptions.ApiName;
                o.ClientSecret = "foo";

                apiOptions.IntrospectionOptions(o);
            };

            var builder = services.AddAuthentication(scheme);

            if (apiOptions.SupportedToken == SupportedTokens.Both || apiOptions.SupportedToken == SupportedTokens.Jwt)
            {
                builder.AddJwtBearer(jwtOptions);
            }

            if (apiOptions.SupportedToken == SupportedTokens.Both || apiOptions.SupportedToken == SupportedTokens.Reference)
            {
                builder.AddOAuth2Introspection("reference", intospectionOptions);
            }

            builder.AddPolicyScheme(scheme, scheme, schemeOptions =>
                {
                    schemeOptions.ForwardDefaultSelector = context =>
                    {
                        var token = apiOptions.TokenRetriever(context.Request);
                        if (!string.IsNullOrWhiteSpace(token))
                        {
                            context.Items["token"] = token;

                            if (!token.Contains("."))
                            {
                                return "reference";
                            }
                        };

                        return null;
                    };
                });

            return services;
        }
    }
}
