# IdentityServer4.AccessTokenValidation

Authentication handler for ASP.NET Core 2 that allows accepting both JWTs and reference tokens in the same API.

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

## Scope validation
In addition to API name checking, you can do more fine-grained audience checks. This package includes some convenience helpers to do that.

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
```csharp
