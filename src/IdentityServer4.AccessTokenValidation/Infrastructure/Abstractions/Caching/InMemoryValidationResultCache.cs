using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Linq;
using IdentityModel;
using Microsoft.AspNet.Authentication;

namespace IdentityServer4.AccessTokenValidation
{
    public class InMemoryValidationResultCache : IValidationResultCache
    {
        private const string CacheKeyPrefix = "identityserver4:token:";
        private readonly IMemoryCache _cache;
        private readonly ISystemClock _clock;

        public InMemoryValidationResultCache(IMemoryCache cache, ISystemClock clock)
        {
            if (cache == null)
            {
                throw new ArgumentNullException(nameof(cache));
            }

            if (clock == null)
            {
                throw new ArgumentNullException(nameof(clock));
            }

            _cache = cache;
            _clock = clock;
        }

        public Task AddAsync(string token, IEnumerable<Claim> claims, TimeSpan cacheDuration)
        {
            var expiryClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Expiration);
            var cacheExpirySetting = _clock.UtcNow.Add(cacheDuration);

            if (expiryClaim != null)
            {
                long epoch;
                if (long.TryParse(expiryClaim.Value, out epoch))
                {
                    var tokenExpiresAt = epoch.ToDateTimeOffsetFromEpoch();
                    if (tokenExpiresAt < cacheExpirySetting)
                    {
                        var cacheOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(tokenExpiresAt);
                        _cache.Set($"{CacheKeyPrefix}{token}", claims, cacheOptions);
                    }
                }
            }
            else
            {
                var cacheOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(cacheExpirySetting);
                _cache.Set($"{CacheKeyPrefix}{token}", claims, cacheOptions);
            }

            return Task.FromResult(0);
        }

        public Task<IEnumerable<Claim>> GetAsync(string token)
        {
            IEnumerable<string> claims = null;
            if(_cache.TryGetValue($"{CacheKeyPrefix}{token}", out claims))
            {
            }

            throw new NotImplementedException();
        }
    }
}
