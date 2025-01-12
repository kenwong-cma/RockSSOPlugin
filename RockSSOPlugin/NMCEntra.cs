using Newtonsoft.Json;
using RestSharp;
using Rock.Attribute;
using Rock.Data;
using Rock.Model;
using Rock.Security.Authentication;
using Rock.Security.Authentication.ExternalRedirectAuthentication;
using Rock.Web.Cache;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.Net;
using System.Web;
using System.Web.Security;

namespace Rock.Security.ExternalAuthentication
{
    /// <summary>
    /// Authenticates a user using ECD (Entra or Azure AD B2C)
    /// </summary>
    [Description("NMC Entra Authentication Provider")]
    [Export(typeof(AuthenticationComponent))]
    [ExportMetadata("ComponentName", "NMC Entra")]

    [UrlLinkField(
        "Authorization URI",
        "Base authorization endpoint (e.g. https://<tenant>.b2clogin.com/<tenantId>/<policy>/oauth2/v2.0/authorize).",
        true, "", "", 0)]
    [UrlLinkField(
        "Token URI",
        "Token endpoint (e.g. https://<tenant>.b2clogin.com/<tenantId>/<policy>/oauth2/v2.0/token).",
        true, "", "", 1)]
    [TextField("Client ID", "The Entra Client ID (Application (client) ID in Azure AD app registration)")]
    [TextField("Client Secret", "The Entra Client Secret")]
    [BooleanField("Enable Debug Mode",
        "Enabling this will generate exceptions at each point of the authentication process. Very useful for troubleshooting.",
        false, "", 5)]
    [Rock.SystemGuid.EntityTypeGuid("FD2B4733-83F1-4283-ADC4-444D744D6360")]
    public class NMCEntra : AuthenticationComponent, IExternalRedirectAuthentication
    {
        private const string EXCEPTION_DEBUG_TEXT = "Entra SSO Debug";

        /// <summary>
        /// Gets the type of the service (External).
        /// </summary>
        public override AuthenticationServiceType ServiceType => AuthenticationServiceType.External;

        /// <summary>
        /// This is a remote authentication provider, so it returns true.
        /// </summary>
        public override bool RequiresRemoteAuthentication => true;

        /// <summary>
        /// Checks if the HttpRequest indicates returning from the external OAuth flow.
        /// </summary>
        public override bool IsReturningFromAuthentication(HttpRequest request)
        {
            // This uses the dictionary approach from Rock, checking for "code" and "state".
            return IsReturningFromExternalAuthentication(request.QueryString.ToSimpleQueryStringDictionary());
        }

        #region GenerateLoginUrl (Legacy)

        /// <summary>
        /// Generates the login URL used by the Rock framework to initiate the OIDC flow (legacy approach).
        /// </summary>
        public override Uri GenerateLoginUrl(HttpRequest request)
        {
            // Gather config values
            string clientId = GetAttributeValue("ClientID");
            string authorizationURI = GetAttributeValue("AuthorizationURI");
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();

            // Ensure the authorization URI ends with "/authorize"
            if (!authorizationURI.EndsWith("/authorize", StringComparison.OrdinalIgnoreCase))
            {
                authorizationURI = $"{authorizationURI.TrimEnd('/')}/authorize";
            }

            // Hardcode or generate a valid redirect URI in your scenario
            // Typically you'd retrieve from a config or build from your Rock environment
            string redirectUri = "https://localhost:6229/page/3";
            string returnUrl = request.QueryString["returnurl"];

            // Build the full login URL
            var newUrl = $"{authorizationURI}?"
                + "response_type=code"
                + $"&client_id={clientId}"
                + $"&redirect_uri={HttpUtility.UrlEncode(redirectUri)}"
                + $"&state={HttpUtility.UrlEncode(returnUrl ?? FormsAuthentication.DefaultUrl)}"
                + "&scope=openid profile email";

            if (debugModeEnabled)
            {
                var logMsg = $"GenerateLoginUrl -> {newUrl}";
                ExceptionLogService.LogException(new Exception(logMsg, new Exception(EXCEPTION_DEBUG_TEXT)));
            }

            return new Uri(newUrl);
        }

        #endregion

        #region IExternalRedirectAuthentication Implementation (Modern Approach)

        /// <summary>
        /// The modern approach in Rock for external redirect flows (exchanging the code, retrieving user info, and setting the auth cookie).
        /// </summary>
        public ExternalRedirectAuthenticationResult Authenticate(ExternalRedirectAuthenticationOptions options)
        {
            var result = new ExternalRedirectAuthenticationResult
            {
                UserName = string.Empty,
                ReturnUrl = options.Parameters.GetValueOrNull("state") // The Rock returnUrl or page
            };

            // 1. Read config
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();
            string clientId = GetAttributeValue("ClientID");
            string clientSecret = GetAttributeValue("ClientSecret");
            string tokenURI = GetAttributeValue("TokenURI");

            // 2. The redirectUri is how we got here
            string redirectUri = options.RedirectUrl;

            try
            {
                // 3. Exchange Authorization Code for Access Token
                var restClient = new RestClient(tokenURI);
                var restRequest = new RestRequest(Method.POST);

                restRequest.AddParameter("grant_type", "authorization_code");
                restRequest.AddParameter("code", options.Parameters.GetValueOrNull("code"));
                restRequest.AddParameter("redirect_uri", redirectUri);
                restRequest.AddParameter("client_id", clientId);
                restRequest.AddParameter("client_secret", clientSecret);

                var restResponse = restClient.Execute(restRequest);

                if (debugModeEnabled)
                {
                    var logMsg = $"ExternalRedirectAuthentication -> Token Response: {restResponse.Content}";
                    ExceptionLogService.LogException(new Exception(logMsg, new Exception(EXCEPTION_DEBUG_TEXT)));
                }

                if (restResponse.StatusCode == HttpStatusCode.OK)
                {
                    var tokenResp = JsonConvert.DeserializeObject<AccessTokenResponse>(restResponse.Content);
                    string accessToken = tokenResp.access_token;

                    // 4. Retrieve user info from Microsoft Graph
                    restClient = new RestClient("https://graph.microsoft.com/v1.0/me");
                    restRequest = new RestRequest(Method.GET);
                    restRequest.AddHeader("Authorization", $"Bearer {accessToken}");

                    var userInfoResponse = restClient.Execute(restRequest);
                    if (debugModeEnabled)
                    {
                        var userInfoMsg = $"ExternalRedirectAuthentication -> User Info: {userInfoResponse.Content}";
                        ExceptionLogService.LogException(new Exception(userInfoMsg, new Exception(EXCEPTION_DEBUG_TEXT)));
                    }

                    if (userInfoResponse.StatusCode == HttpStatusCode.OK)
                    {
                        // 5. Map user claims to Rock user
                        var office365User = JsonConvert.DeserializeObject<Office365_User>(userInfoResponse.Content);
                        string userName = GetOffice365User(office365User, accessToken);

                        if (!string.IsNullOrWhiteSpace(userName))
                        {
                            // 6. Set Rock auth cookie
                            Rock.Security.Authorization.SetAuthCookie(userName, false, false);

                            result.IsAuthenticated = true;
                            result.UserName = userName;
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

        /// <summary>
        /// Generates the external login URL for the new approach in Rock (UI calls this to get the redirect).
        /// Similar to GenerateLoginUrl, but for IExternalRedirectAuthentication usage.
        /// </summary>
        public Uri GenerateExternalLoginUrl(string externalProviderReturnUrl, string successfulAuthenticationRedirectUrl)
        {
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();
            string clientId = GetAttributeValue("ClientID");
            string authorizationURI = GetAttributeValue("AuthorizationURI");

            // Ensure ends with "/authorize"
            if (!authorizationURI.EndsWith("/authorize", StringComparison.OrdinalIgnoreCase))
            {
                authorizationURI = $"{authorizationURI.TrimEnd('/')}/authorize";
            }

            // The "successfulAuthenticationRedirectUrl" is typically where the user returns after external auth
            // e.g. https://<your_rock_server>/page/<callback_page>
            string newUrl = $"{authorizationURI}?"
                + "response_type=code"
                + $"&client_id={clientId}"
                + $"&redirect_uri={HttpUtility.UrlEncode(successfulAuthenticationRedirectUrl)}"
                + $"&state={HttpUtility.UrlEncode(externalProviderReturnUrl ?? FormsAuthentication.DefaultUrl)}"
                + "&scope=openid profile email";

            if (debugModeEnabled)
            {
                var logMsg = $"GenerateExternalLoginUrl -> {newUrl}";
                ExceptionLogService.LogException(new Exception(logMsg, new Exception(EXCEPTION_DEBUG_TEXT)));
            }

            return new Uri(newUrl);
        }

        public bool IsReturningFromExternalAuthentication(IDictionary<string, string> parameters)
        {
            // Typically ensure 'code' and 'state' exist
            return !string.IsNullOrWhiteSpace(parameters.GetValueOrNull("code"))
                && !string.IsNullOrWhiteSpace(parameters.GetValueOrNull("state"));
        }

        #endregion

        #region Legacy Rock Overrides (If Rock calls them)

        /// <inheritdoc/>
        public override bool Authenticate(HttpRequest request, out string username, out string returnUrl)
        {
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();
            username = string.Empty;
            returnUrl = request.QueryString["state"];

            // 1. Gather config
            string tokenURI = GetAttributeValue("TokenURI");
            string code = request.QueryString["code"];
            string redirectUri = GetRedirectUrl(request);
            string clientId = GetAttributeValue("ClientID");
            string clientSecret = GetAttributeValue("ClientSecret");

            try
            {
                // 2. Exchange Code for Token
                var restClient = new RestClient(tokenURI);
                var restRequest = new RestRequest(Method.POST);
                restRequest.AddParameter("grant_type", "authorization_code");
                restRequest.AddParameter("code", code);
                restRequest.AddParameter("redirect_uri", redirectUri);
                restRequest.AddParameter("client_id", clientId);
                restRequest.AddParameter("client_secret", clientSecret);

                var restResponse = restClient.Execute(restRequest);
                if (debugModeEnabled)
                {
                    var debugMsg = $"Authenticate() -> Token Exchange: {restResponse.Content}";
                    ExceptionLogService.LogException(new Exception(debugMsg, new Exception(EXCEPTION_DEBUG_TEXT)));
                }

                if (restResponse.StatusCode == HttpStatusCode.OK)
                {
                    var tokenResp = JsonConvert.DeserializeObject<Office365_AccessTokenResponse>(restResponse.Content);
                    string accessToken = tokenResp.access_token;

                    // 3. Get user from Graph
                    restClient = new RestClient("https://graph.microsoft.com/v1.0/me");
                    restRequest = new RestRequest(Method.GET);
                    restRequest.AddHeader("Authorization", $"Bearer {accessToken}");

                    restResponse = restClient.Execute(restRequest);
                    if (debugModeEnabled)
                    {
                        var userInfoMsg = $"Authenticate() -> User Info: {restResponse.Content}";
                        ExceptionLogService.LogException(new Exception(userInfoMsg, new Exception(EXCEPTION_DEBUG_TEXT)));
                    }

                    if (restResponse.StatusCode == HttpStatusCode.OK)
                    {
                        var office365User = JsonConvert.DeserializeObject<Office365_User>(restResponse.Content);
                        username = GetOffice365User(office365User, accessToken);

                        // 4. Set the Rock auth cookie
                        if (!string.IsNullOrWhiteSpace(username))
                        {
                            Rock.Security.Authorization.SetAuthCookie(username, false, false);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ExceptionLogService.LogException(ex, HttpContext.Current);
            }

            return !string.IsNullOrWhiteSpace(username);
        }

        /// <inheritdoc/>
        public override string ImageUrl() => string.Empty;

        /// <inheritdoc/>
        public override bool Authenticate(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        public override string EncodePassword(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        public override bool SupportsChangePassword => false;

        public override bool ChangePassword(UserLogin user, string oldPassword, string newPassword, out string warningMessage)
        {
            warningMessage = "not supported";
            return false;
        }

        public override void SetPassword(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region Helper: GetRedirectUrl

        private string GetRedirectUrl(HttpRequest request)
        {
            // Example: build from the current Rock page path
            // e.g. https://<your_rock_domain>/page/3
            Uri uri = new Uri(request.UrlProxySafe().ToString());
            return uri.Scheme + "://" + uri.GetComponents(UriComponents.HostAndPort, UriFormat.UriEscaped) + uri.LocalPath;
        }

        #endregion

        #region Models

        /// <summary>
        /// Minimal Access Token Response
        /// </summary>
        public class AccessTokenResponse
        {
            public string access_token { get; set; }
            public int expires_in { get; set; }
            public string token_type { get; set; }
        }

        public class Office365_AccessTokenResponse
        {
            public string access_token { get; set; }
            public int expires_in { get; set; }
            public string token_type { get; set; }
            public string scope { get; set; }
            public int ext_expires_int { get; set; }
        }

        public class Office365_User
        {
            public string id { get; set; }
            public string displayName { get; set; }
            public string givenName { get; set; }
            public string jobTitle { get; set; }
            public string mail { get; set; }
            public string mobilePhone { get; set; }
            public string officeLocation { get; set; }
            public string preferredLanguage { get; set; }
            public string surName { get; set; }
            public string userPrincipalName { get; set; }
        }

        /// <summary>
        /// Maps the user from the retrieved JSON to a Rock Person/UserLogin
        /// </summary>
        public static string GetOffice365User(Office365_User office365User, string accessToken = "")
        {
            return CreateOrRetrieveUser(office365User?.userPrincipalName, office365User?.givenName, office365User?.surName, "office365", accessToken);
        }

        private static string CreateOrRetrieveUser(string email, string firstName, string lastName, string loginSource, string accessToken)
        {
            if (accessToken.IsNullOrWhiteSpace()) return null;
            if (email.IsNullOrWhiteSpace()) return null;

            string userName = $"{loginSource}_{email}";
            UserLogin user = null;

            using (var rockContext = new RockContext())
            {
                var userLoginService = new UserLoginService(rockContext);
                user = userLoginService.GetByUserName(userName);

                if (user == null)
                {
                    // Attempt to find an existing Person
                    Person person = null;
                    if (email.IsNotNullOrWhiteSpace())
                    {
                        var personService = new PersonService(rockContext);
                        person = personService.FindPerson(firstName, lastName, email, true);
                    }

                    var personRecordTypeId = DefinedValueCache.Get(Rock.SystemGuid.DefinedValue.PERSON_RECORD_TYPE_PERSON.AsGuid()).Id;
                    var personStatusPending = DefinedValueCache.Get(Rock.SystemGuid.DefinedValue.PERSON_RECORD_STATUS_PENDING.AsGuid()).Id;

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
                            int typeId = EntityTypeCache.Get(typeof(NMCEntra)).Id;
                            user = UserLoginService.Create(rockContext, person, AuthenticationServiceType.External, typeId, userName, loginSource, true);
                        }
                    });
                }
            }

            return user?.UserName;
        }

        #endregion
    }
}
