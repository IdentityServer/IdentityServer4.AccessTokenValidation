using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JwtEventSample
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {
            app.UseIdentityServerAuthentication(new IdentityServerAuthenticationOptions
            {
                Authority = "AAA",
                ScopeName ="Api",
                RequireHttpsMetadata =false,
                JwtBearerEvents = new JwtBearerEvents()
                {
                    OnMessageReceived = e =>
                    {
                        ClaimsIdentity claimsIdentity = new ClaimsIdentity("Custom");
                        var claims = new List<Claim>();
                        claims.Add(new Claim(ClaimTypes.Name, "test"));
                        claimsIdentity.AddClaims(claims);
                        ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                        e.HttpContext.User = claimsPrincipal;
                        e.SkipToNextMiddleware();
                        return Task.FromResult(0);
                    }
                }
            });
            app.Use(async (context, next) =>
            {
                // Use this if options.AutomaticAuthenticate = false
                // var user = await context.Authentication.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);

                var user = context.User; // We can do this because of  options.AutomaticAuthenticate = true;
                if (user?.Identity?.IsAuthenticated ?? false)
                {
                    await next();
                }
                else
                {
                    // We can do this because of options.AutomaticChallenge = true;
                    await context.Authentication.ChallengeAsync();
                }
            });

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync(context.User.Identity.IsAuthenticated.ToString());
            }); 
        }
    }
}
