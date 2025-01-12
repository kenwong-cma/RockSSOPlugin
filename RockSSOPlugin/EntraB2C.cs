using Newtonsoft.Json;
using RestSharp;
using Rock;
using Rock.Attribute;
using Rock.Data;
using Rock.Model;
using Rock.Security;
using Rock.Security.Authentication;
using Rock.Security.Authentication.ExternalRedirectAuthentication;
using Rock.Web.Cache;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Security;

namespace com.thealliancecanada.RockSSOPlugin
{
    /// <summary>
    /// Authenticates a user using Entra B2C
    /// </summary>
    [Description("Entra B2C Authentication Provider")]
    [Export(typeof(AuthenticationComponent))]
    [ExportMetadata("ComponentName", "Entra B2C")]

    [UrlLinkField("Authorization URI", "URI for authorization requests from Entra B2C.", true, "", "", 0)]
    [UrlLinkField("Token URI", "URI for token requests from Entra B2C.", true, "", "", 1)]
    [TextField("Client Id", "Client Id from your Entra B2C App Registration.", true, "", "", 3)]
    [TextField("Client Secret", "Client Secret from your Entra B2C App Registration.", true, "", "", 4)]
    [BooleanField("Enable Debug Mode", "Enable to log detailed debug information.", false, "", 5)]
    public class EntraB2C : AuthenticationComponent, IExternalRedirectAuthentication
    {
        private const string EXCEPTION_DEBUG_TEXT = "Entra B2C Debug";

        public override AuthenticationServiceType ServiceType => AuthenticationServiceType.External;
        public override bool RequiresRemoteAuthentication => true;

        public override string LoginButtonText => "<i class='fa fa-user'></i> Entra B2C";

        public override bool IsReturningFromAuthentication(HttpRequest request)
            => !string.IsNullOrWhiteSpace(request.QueryString["code"]);

        public bool IsReturningFromExternalAuthentication(IDictionary<string, string> parameters)
            => !string.IsNullOrWhiteSpace(parameters.GetValueOrNull("code"));

        public override Uri GenerateLoginUrl(HttpRequest request)
        {
            string authorizationURI = GetAttributeValue("AuthorizationURI");
            string clientId = GetAttributeValue("ClientId");
            string returnUrl = request.QueryString["returnurl"];
            string redirectUri = GetRedirectUrl(request);
            // Adjust scopes as needed for Entra B2C
            string newUrl = string.Format(
                "{0}?client_id={1}&redirect_uri={2}&response_type=code&state={3}&scope=openid profile email",
                authorizationURI,
                clientId,
                HttpUtility.UrlEncode(redirectUri),
                HttpUtility.UrlEncode(returnUrl ?? FormsAuthentication.DefaultUrl)
            );

            return new Uri(newUrl);
        }

        public override bool Authenticate(HttpRequest request, out string username, out string returnUrl)
        {
            username = string.Empty;
            returnUrl = request.QueryString["state"];
            string redirectUri = GetRedirectUrl(request);
            string tokenURI = GetAttributeValue("TokenURI");
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();

            try
            {
                var restClient = new RestClient(tokenURI);
                var restRequest = new RestRequest(Method.POST);
                restRequest.AddParameter("code", request.QueryString["code"]);
                restRequest.AddParameter("client_id", GetAttributeValue("ClientId"));
                restRequest.AddParameter("client_secret", GetAttributeValue("ClientSecret"));
                restRequest.AddParameter("redirect_uri", redirectUri);
                restRequest.AddParameter("grant_type", "authorization_code");
                restRequest.AddParameter("scope", "openid");

                var restResponse = restClient.Execute(restRequest);

                if (debugModeEnabled)
                {
                    ExceptionLogService.LogException(new Exception($"Token Response: {restResponse.Content}", new Exception(EXCEPTION_DEBUG_TEXT)));
                }

                if (restResponse.StatusCode == HttpStatusCode.OK)
                {
                    // Parse the token response
                    var tokenResponse = JsonConvert.DeserializeObject<B2C_AccessTokenResponse>(restResponse.Content);
                    string idToken = tokenResponse.id_token;  // Expect an id_token field from B2C

                    if (!string.IsNullOrWhiteSpace(idToken))
                    {
                        // Decode the JWT
                        var handler = new JwtSecurityTokenHandler();
                        var jwtToken = handler.ReadJwtToken(idToken);

                        foreach (var claim in jwtToken.Claims)
                        {
                            ExceptionLogService.LogException(new Exception($"Claim: {claim.Type} = {claim.Value}", new Exception(EXCEPTION_DEBUG_TEXT)));
                        }

                        // Extract claims (adjust claim types based on your B2C configuration)
                        string email = jwtToken?.Claims.FirstOrDefault(c => c.Type == "email")?.Value
             ?? jwtToken?.Claims.FirstOrDefault(c => c.Type == "emails")?.Value
             ?? jwtToken?.Claims.FirstOrDefault(c => c.Type == "signInNames.emailAddress")?.Value;

                        string givenName = jwtToken?.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
                        string surname = jwtToken?.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value;

                        // Construct a unique username identifier for the local system
                        string userKey = email != null ? email.ToLowerInvariant() : Guid.NewGuid().ToString();
                        username = $"EntraB2C_{userKey}";

                        // Optionally use GetB2CUser to create or retrieve the user in Rock
                        username = GetB2CUser(new B2C_User
                        {
                            id = jwtToken?.Claims.FirstOrDefault(c => c.Type == "oid")?.Value,
                            givenName = givenName,
                            surname = surname,
                            userPrincipalName = email,
                            displayName = $"{givenName} {surname}"
                        }, idToken);
                    }
                }
            }
            catch (Exception ex)
            {
                ExceptionLogService.LogException(ex, HttpContext.Current);
            }

            return !string.IsNullOrWhiteSpace(username);
        }

        public ExternalRedirectAuthenticationResult Authenticate(ExternalRedirectAuthenticationOptions options)
        {
            var result = new ExternalRedirectAuthenticationResult
            {
                UserName = string.Empty,
                ReturnUrl = options.Parameters.GetValueOrNull("State")
            };
            string tokenURI = GetAttributeValue("TokenURI");
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();

            try
            {
                var restClient = new RestClient(tokenURI);
                var restRequest = new RestRequest(Method.POST);
                restRequest.AddParameter("code", options.Parameters.GetValueOrNull("code"));
                restRequest.AddParameter("client_id", GetAttributeValue("ClientId"));
                restRequest.AddParameter("client_secret", GetAttributeValue("ClientSecret"));
                restRequest.AddParameter("redirect_uri", options.RedirectUrl);
                restRequest.AddParameter("grant_type", "authorization_code");
                // Request the id_token explicitly if not included by default
                restRequest.AddParameter("scope", "openid");

                var restResponse = restClient.Execute(restRequest);

                if (debugModeEnabled)
                {
                    ExceptionLogService.LogException(new Exception($"Token Response: {restResponse.Content}", new Exception(EXCEPTION_DEBUG_TEXT)));
                }

                if (restResponse.StatusCode == HttpStatusCode.OK)
                {
                    var tokenResponse = JsonConvert.DeserializeObject<B2C_AccessTokenResponse>(restResponse.Content);
                    string idToken = tokenResponse.id_token;

                    if (!string.IsNullOrWhiteSpace(idToken))
                    {
                        var handler = new JwtSecurityTokenHandler();
                        var jwtToken = handler.ReadJwtToken(idToken);

                        foreach (var claim in jwtToken.Claims)
                        {
                            ExceptionLogService.LogException(new Exception($"Claim: {claim.Type} = {claim.Value}", new Exception(EXCEPTION_DEBUG_TEXT)));
                        }

                        // Extract claims (adjust claim types based on your B2C configuration)
                        string email = jwtToken?.Claims.FirstOrDefault(c => c.Type == "email")?.Value
             ?? jwtToken?.Claims.FirstOrDefault(c => c.Type == "emails")?.Value
             ?? jwtToken?.Claims.FirstOrDefault(c => c.Type == "signInNames.emailAddress")?.Value;


                        string givenName = jwtToken?.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
                        string surname = jwtToken?.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value;

                        // Construct a unique username identifier for the local system
                        string userKey = email != null ? email.ToLowerInvariant() : Guid.NewGuid().ToString();
                        var b2cUser = new B2C_User
                        {
                            id = jwtToken.Claims.FirstOrDefault(c => c.Type == "oid")?.Value,
                            givenName = givenName,
                            surname = surname,
                            userPrincipalName = email,
                            displayName = $"{givenName} {surname}"
                        };

                        result.UserName = GetB2CUser(b2cUser, idToken);
                        result.IsAuthenticated = !string.IsNullOrWhiteSpace(result.UserName);

                        if (debugModeEnabled)
                        {
                            ExceptionLogService.LogException(new Exception($"UserName: {result.UserName}", new Exception(EXCEPTION_DEBUG_TEXT)));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ExceptionLogService.LogException(ex, HttpContext.Current);
            }

            return result;
        }

        public override string ImageUrl()
        {
            return string.Empty; // Optional: return an image URL/icon for the button
        }

        private string GetRedirectUrl(HttpRequest request)
        {
            Uri uri = new Uri(request.UrlProxySafe().ToString());
            return uri.Scheme + "://" + uri.GetComponents(UriComponents.HostAndPort, UriFormat.UriEscaped) + uri.LocalPath;
        }

        public Uri GenerateExternalLoginUrl(string externalProviderReturnUrl, string successfulAuthenticationRedirectUrl)
        {
            string authorizationURI = GetAttributeValue("AuthorizationURI");
            string clientId = GetAttributeValue("ClientId");
            string returnUrl = HttpUtility.UrlEncode(externalProviderReturnUrl);
            string redirectUri = HttpUtility.UrlEncode(successfulAuthenticationRedirectUrl ?? FormsAuthentication.DefaultUrl);
            string newUrl = string.Format(
                "{0}?client_id={1}&redirect_uri={2}&state={3}&response_type=code&scope=openid profile email",
                authorizationURI,
                clientId,
                returnUrl,
                redirectUri
            );

            return new Uri(newUrl);
        }


        // Implement password/auth-related methods if necessary for your scenario:
        public override bool Authenticate(UserLogin user, string password)
            => throw new NotImplementedException();
        public override string EncodePassword(UserLogin user, string password)
            => throw new NotImplementedException();
        public override bool SupportsChangePassword => false;
        public override bool ChangePassword(UserLogin user, string oldPassword, string newPassword, out string warningMessage)
        {
            warningMessage = "not supported";
            return false;
        }
        public override void SetPassword(UserLogin user, string password)
            => throw new NotImplementedException();

        // Update the user retrieval/creation logic for Entra B2C
        private string GetB2CUser(B2C_User b2cUser, string accessToken = "")
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return null;
            }

            string username = string.Empty;
            string email = b2cUser.userPrincipalName;
            string b2cId = b2cUser.id;
            string userName = "EntraB2C_" + email;

            UserLogin user = null;
            using (var rockContext = new RockContext())
            {
                var userLoginService = new UserLoginService(rockContext);
                user = userLoginService.GetByUserName(userName);

                if (user == null)
                {
                    string lastName = b2cUser.surname;
                    string firstName = b2cUser.givenName;
                    Person person = null;

                    if (!string.IsNullOrWhiteSpace(email))
                    {
                        var personService = new PersonService(rockContext);
                        person = personService.FindPerson(firstName, lastName, email, true);
                    }

                    int personRecordTypeId = DefinedValueCache.Get(Rock.SystemGuid.DefinedValue.PERSON_RECORD_TYPE_PERSON.AsGuid()).Id;
                    int personStatusPending = DefinedValueCache.Get(Rock.SystemGuid.DefinedValue.PERSON_RECORD_STATUS_PENDING.AsGuid()).Id;

                    rockContext.WrapTransaction(() =>
                    {
                        if (person == null)
                        {
                            person = new Person
                            {
                                IsSystem = false,
                                RecordTypeValueId = personRecordTypeId,
                                RecordStatusValueId = personStatusPending,
                                FirstName = firstName,
                                LastName = lastName,
                                Email = email,
                                IsEmailActive = true,
                                EmailPreference = EmailPreference.EmailAllowed,
                                Gender = Gender.Unknown
                            };
                            PersonService.SaveNewPerson(person, rockContext, null, false);
                        }

                        if (person != null)
                        {
                            int typeId = EntityTypeCache.Get(typeof(EntraB2C)).Id;
                            user = UserLoginService.Create(rockContext, person, AuthenticationServiceType.External, typeId, userName, "entrab2c", true);
                        }
                    });
                }

                if (user != null)
                {
                    return user.UserName;
                }
            }
            return username;
        }

        public override bool IsConfiguredForTwoFactorAuthentication() => true;

        #region Models

        public class B2C_AccessTokenResponse
        {
            public string access_token { get; set; }
            public string id_token { get; set; }  // Add this property
            public int expires_in { get; set; }
            public string token_type { get; set; }
            public string scope { get; set; }
            public int ext_expires_in { get; set; }
        }

        public class B2C_User
        {
            public string id { get; set; }
            public string displayName { get; set; }
            public string givenName { get; set; }
            public string surname { get; set; }
            public string userPrincipalName { get; set; }
            // Add any additional properties as needed based on the Entra B2C user response
        }

        #endregion
    }
}
