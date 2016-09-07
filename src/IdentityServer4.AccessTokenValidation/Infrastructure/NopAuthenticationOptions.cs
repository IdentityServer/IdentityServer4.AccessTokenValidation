// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Microsoft.AspNetCore.Builder
{
    internal class NopAuthenticationOptions : AuthenticationOptions
    {
        public NopAuthenticationOptions()
        {
            AutomaticAuthenticate = true;
            AutomaticChallenge = true;
        }
    }
}