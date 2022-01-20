using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;


namespace B2CWebApp.Controllers
{
    
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            // Get the claims
            var identity = User.Identity as ClaimsIdentity;
            var userClaims = identity.Claims;
            var userObjectId = userClaims.Where(c => c.Type == ClaimTypes.NameIdentifier)
                   .Select(c => c.Value).SingleOrDefault();

            ViewBag.Claims = userClaims;

            return View();
        }

        
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            // Get the claims
            var identity = User.Identity as ClaimsIdentity;
            var userClaims = identity.Claims;
            var userObjectId = userClaims.Where(c => c.Type == ClaimTypes.NameIdentifier)
                   .Select(c => c.Value).SingleOrDefault();

            ViewBag.Claims = userClaims;

            // AcquireToken
            string authority    = "https://login.microsoftonline.com/williamfiddesb2c.onmicrosoft.com";
            string ClientId     = "9f76194a-97f3-4bc0-b871-51f5e83c4da4";
            string ClientSecret = "0hBTqWclKqHf/7zkp2AdouSjLUMLmze+XBHk5PJINas=";
            string ResourceId   = "https://graph.microsoft.com";

            //ClientCredential ClientCreds = new ClientCredential(ClientId, ClientSecret);

            //AuthenticationContext aadContext = new AuthenticationContext(authority);
            //AuthenticationResult result = aadContext.AcquireTokenAsync(ResourceId, ClientCreds).Result;

            // Using the token
            string props = "";
            props += "accountEnabled";
            props += ",signInNames";
            props += ",creationType";
            props += ",displayName";
            props += ",mailNickname";
            props += ",passwordProfile";
            props += ",passwordPolicies";
            props += ",businessPhones";
            props += ",givenName";
            props += ",mail";
            props += ",mobilePhone";
            props += ",officeLocation";
            props += ",preferredLanguage";
            props += ",surname";
            props += ",userPrincipalName";
            props += ",id";

            string resourceUrl = $"https://graph.microsoft.com/v1.0/users/{userObjectId}?$select={props}";
            HttpClient client = new HttpClient();
            //client.DefaultRequestHeaders.Add("Authorization", result.CreateAuthorizationHeader());

            //HttpResponseMessage graphResponse = client.GetAsync(resourceUrl).Result;
            //string content = graphResponse.Content.ReadAsStringAsync().Result;
            
            
            ViewBag.Claims = userClaims;
    

            return View();
        }

        [Authorize]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public ActionResult Error()
        {
            
            string error_message = Request.Params["message"];
            string error_description = Request.Params["error_description"];

            ViewBag.Message = $"{error_message}: {error_description}";

            return View();
        }



    }

    
}