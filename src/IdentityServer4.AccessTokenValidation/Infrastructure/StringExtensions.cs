namespace IdentityServer4.AccessTokenValidation
{
    internal static class StringExtensions
    {
        public static string EnsureTrailingSlash(this string input)
        {
            if (!input.EndsWith("/"))
            {
                return input + "/";
            }

            return input;
        }
    }
}
