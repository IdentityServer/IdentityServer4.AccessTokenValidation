using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.JwtBearer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerBearerTokenOptions : JwtBearerOptions, IIdentityServerBearerTokenBaseOptions
    {
        public IdentityServerBearerTokenOptions()
        {
            ValidationResultCacheDuration = TimeSpan.FromMinutes(5);
            RequiredScopes = Enumerable.Empty<string>();
            PreserveAccessToken = false;
        }

        public IEnumerable<string> RequiredScopes { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to preserve the access token as a claim. Defaults to false.
        /// </summary>
        /// <value>
        ///   <c>true</c> if access token is preserved; otherwise, <c>false</c>.
        /// </value>
        public bool PreserveAccessToken { get; set; }

        public TimeSpan ValidationResultCacheDuration { get; set; }
    }
}
