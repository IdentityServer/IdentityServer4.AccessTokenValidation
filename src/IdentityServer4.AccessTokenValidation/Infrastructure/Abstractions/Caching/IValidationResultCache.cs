using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    /// <summary>
    /// Interface for caching then token validation result
    /// </summary>
    public interface IValidationResultCache
    {
        /// <summary>
        /// Add a validation result
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        Task AddAsync(string token, IEnumerable<Claim> claims, TimeSpan cacheDuration);

        /// <summary>
        /// Retrieves a validation result
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        Task<IEnumerable<Claim>> GetAsync(string token);
    }
}
