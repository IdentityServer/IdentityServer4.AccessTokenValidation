using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace JwtEventSample
{
    public class Test
    {
        private readonly TestServer _server;
        private readonly HttpClient _client;
        public Test()
        {
            // Arrange
            _server = new TestServer(new WebHostBuilder()
                .UseStartup<Startup>());
            _client = _server.CreateClient();
        }

        [Fact]
        public async Task ShouldBeTrue()
        {
            _client.DefaultRequestHeaders.Add("Authorization", "Bearer test....");
            // Act
            var response = await _client.GetAsync("/");

            // Assert
            Assert.Equal("True", await response.Content.ReadAsStringAsync());
        }
    }
}
