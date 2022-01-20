using Microsoft.Identity.Client;

using System.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Threading.Tasks;
using System.Web;

using System.Net;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace B2CWebApp
{
    public partial class Startup
    {
        // App config settings
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        // B2C policy identifiers
        public static string SignUpSignInPolicyId = ConfigurationManager.AppSettings["ida:SignUpSignInPolicyId"];
        public static string ProfilePolicyId = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        public void ConfigureAuth(IAppBuilder app)
        {
            //Microsoft.IdentityModel.Protocols.IConfigurationManager<OpenIdConnectConfiguration> publicConfigurationManager = new Microsoft.IdentityModel.Protocols.ConfigurationManager<OpenIdConnectConfiguration>($"https://williamfiddesb2c.b2clogin.com/williamfiddesb2c.onmicrosoft.com/{SignUpSignInPolicyId}/v2.0/.well-known/openid-configuration.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            //OpenIdConnectConfiguration publicOpenIdConfig = publicConfigurationManager.GetConfigurationAsync(System.Threading.CancellationToken.None).GetAwaiter().GetResult();


            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                Provider = new CookieAuthenticationProvider
                {
                    OnResponseSignIn = context =>
                    {
                        context.Properties.AllowRefresh = true;
                        context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(24);
                    }
                }
            });

            // Configure OpenID Connect middleware for each policy

            var ProfileEditPolicyOptions = CreateOptionsFromPolicy(ProfilePolicyId);
            var SignUpSignInPolicyOptions = CreateOptionsFromPolicy(SignUpSignInPolicyId);

            app.UseOpenIdConnectAuthentication(ProfileEditPolicyOptions);
            app.UseOpenIdConnectAuthentication(SignUpSignInPolicyOptions);
            

            
        }

        // Used for avoiding yellow-screen-of-death
        private Task AuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            HttpContext context = HttpContext.Current;
            string error_description = context.Request.Params["error_description"];

            notification.HandleResponse();
            if (error_description != String.Empty)
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message + "&error_description=" + error_description);
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }

        private OpenIdConnectAuthenticationOptions CreateOptionsFromPolicy(string policy)
        {
            return new OpenIdConnectAuthenticationOptions 
            {

                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                //MetadataAddress = String.Format(aadInstance, tenant, policy),
                //Authority = "https://login.microsoftonline.com/tfp/" + tenant + "/" + policy,

                

                MetadataAddress = $"https://williamfiddesb2c.b2clogin.com/williamfiddesb2c.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration",

                AuthenticationType = policy,

                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = clientId,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
                Scope = "openid "+clientId,
                ResponseType = "token id_token",

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = OnRedirectToIdentityProvider
                },

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    SaveSigninToken = true //important to save the token in boostrapcontext
                }
            };
        }

        private Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var policy = notification.OwinContext.Get<string>("Policy");
            string issuerAddress = notification.ProtocolMessage.IssuerAddress;

            if (!string.IsNullOrEmpty(policy) && !policy.Equals(SignUpSignInPolicyId))
            {
                notification.ProtocolMessage.Scope = OpenIdConnectScope.OpenId;
                notification.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                
                notification.ProtocolMessage.IssuerAddress = notification.ProtocolMessage.IssuerAddress.ToLower().Replace(SignUpSignInPolicyId.ToLower(), policy.ToLower());

            }

            return Task.FromResult(0);
        }

        /*
         * Catch any failures received by the authentication middleware and handle appropriately
         */
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();

            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (notification.ProtocolMessage.ErrorDescription != null && notification.ProtocolMessage.ErrorDescription.Contains("AADB2C90118"))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                notification.Response.Redirect("/Account/ResetPassword");
            }
            else if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }
    }
}
