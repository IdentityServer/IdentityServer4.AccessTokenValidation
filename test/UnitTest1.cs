using FluentAssertions;
using IdentityModel.Client;
using System.Net;
using System.Threading.Tasks;
using Tests.Util;
using Xunit;

namespace Tests
{
    public class UnitTest1
    {
        [Fact]
        public async Task no_token_should_return_401()
        {
            var client = PipelineFactory.CreateClient(options =>
            {
                options.Authority = "https://authority";
                options.ApiName = "api1";
            });

            var response = await client.GetAsync("http://api");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task invalid_reference_token_should_return_401()
        {
            var client = PipelineFactory.CreateClient(options =>
            {
                options.Authority = "https://demo.identityserver.io";
                options.ApiName = "api1";
                options.ApiSecret = "secret";
            });

            client.SetBearerToken("invalid");
            var response = await client.GetAsync("http://api");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task invalid_jwt_token_should_return_401()
        {
            var client = PipelineFactory.CreateClient(options =>
            {
                options.Authority = "https://demo.identityserver.io";
                options.ApiName = "api1";
            });

            client.SetBearerToken("header.payload.signature");
            var response = await client.GetAsync("http://api");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
    }
}
