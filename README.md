# IdentityServer4.AccessTokenValidation
Authentication handler for ASP.NET Core 2 that allows accepting both JWTs and reference tokens in the same API.

Technically this handler is a decorator over both the Microsoft [JWT handler](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer/) as well as our OAuth 2 [introspection handler](https://www.nuget.org/packages/IdentityModel.AspNetCore.OAuth2Introspection/). If you only need to support one token type only, we recommend using the underlying handlers directly.

## Issues
For issues, use the [consolidated IdentityServer4 issue tracker](https://github.com/IdentityServer/IdentityServer4/issues).

## JWT Usage
Simply specify authority and API name (aka audience):

```csharp
services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
    .AddIdentityServerAuthentication(options =>
    {
        options.Authority = "https://demo.identityserver.io";
        options.ApiName = "api1";
    });
```

## Enable reference tokens
Additionally specify the API secret for the introspection endpoint:

```csharp
services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
    .AddIdentityServerAuthentication(options =>
    {
        options.Authority = "https://demo.identityserver.io";
        options.ApiName = "api1";
        options.ApiSecret = "secret";
    });
```

## Specifying the underlying handler options directly
In case you need access to a setting that the combined options don't expose, you can fallback to configuring the underlying handler directly.

```csharp
services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
    .AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme,
        jwtOptions =>
        {
            // jwt bearer options
        },
        referenceOptions =>
        {
            // oauth2 introspection options
        });
```

## Scope validation
In addition to API name checking, you can do more fine-grained scope checks. This package includes some convenience helpers to do that.

### Create a global authorization policy

```csharp
services
    .AddMvcCore(options =>
    {
        // require scope1 or scope2
        var policy = ScopePolicy.Create("scope1", "scope2");
        options.Filters.Add(new AuthorizeFilter(policy));
    })
    .AddJsonFormatters()
    .AddAuthorization();
```

### Composing a scope policy

```csharp
services.AddAuthorization(options =>
{
    options.AddPolicy("myPolicy", builder =>
    {
        // require scope1
        builder.RequireScope("scope1");
        // and require scope2 or scope3
        builder.RequireScope("scope2", "scope3");
    });
});
```
