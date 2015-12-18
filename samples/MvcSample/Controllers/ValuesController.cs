using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Mvc;

namespace MvcSample.Controllers
{
    [Authorize]
    [Route("values")]
    public class ValuesController : Controller
    {
        [HttpGet]
        public string[] GetValues()
        {
            return new[]
            {
                "value 1",
                "value 2"
            };
        }
    }
}
