using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNet.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods for setting up access token validation services in an <see cref="IServiceCollection" />.
    /// </summary>
    public static class AccessTokenValidationServiceCollectionExtensions
    {
        /// <summary>
        /// Adds access token validation services to the specified <see cref="IServiceCollection" />.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns> 
        public static IServiceCollection AddAccessTokenValidation(this IServiceCollection services)
        {
            services.AddAuthentication();   
            return services;
        }

        /// <summary>
        /// Adds access token validation services to the specified <see cref="IServiceCollection" /> with 
        /// default in-memory validation result caching.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns> 
        /// <seealso cref="ISystemClock" />
        /// <seealso cref="SystemClock" />
        /// <seealso cref="IValidationResultCache" />
        /// <seealso cref="InMemoryValidationResultCache" />
        public static IServiceCollection AddAccessTokenValidationWithCaching(this IServiceCollection services)
        {
            services.AddCaching();
            services.AddAuthentication();
            services.TryAdd(ServiceDescriptor.Singleton<ISystemClock, SystemClock>());
            services.TryAdd(ServiceDescriptor.Singleton<IValidationResultCache, InMemoryValidationResultCache>());

            return services;
        }
    }
}
