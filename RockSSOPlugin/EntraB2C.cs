using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
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
using System.Security.Claims;
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
    [UrlLinkField("WellKnown",
    "URI for fetching the OpenID Connect configuration from Entra B2C.",
    true,
    "https://theallianceca.b2clogin.com/theallianceca.onmicrosoft.com/B2C_1A_SIGNUP_SIGNIN/v2.0/.well-known/openid-configuration",
    "",
    6)]
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
            string wellKnownUri = GetAttributeValue("WellKnown");
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
                restRequest.AddParameter("scope", "openid profile email");

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
                        var handler = new JwtSecurityTokenHandler();

                        // Retrieve the OpenID Connect metadata document
                        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                            wellKnownUri,
                            new OpenIdConnectConfigurationRetriever());

                        OpenIdConnectConfiguration openIdConfig = null;
                        try
                        {
                            openIdConfig = configurationManager.GetConfigurationAsync().Result;
                        }
                        catch (Exception ex)
                        {
                            ExceptionLogService.LogException(new Exception("Failed to retrieve OpenID configuration", ex));
                            throw;
                        }

                        var validationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidIssuer = openIdConfig.Issuer,
                            ValidateAudience = true,
                            ValidAudience = GetAttributeValue("ClientId"),
                            ValidateLifetime = true,
                            IssuerSigningKeys = openIdConfig.SigningKeys,
                            // Optional: Validate the token's nonce, if used
                        };

                        if (debugModeEnabled)
                        {
                            ExceptionLogService.LogException(new Exception($"Validation Parameters: Issuer={validationParameters.ValidIssuer}, Audience={validationParameters.ValidAudience}", new Exception(EXCEPTION_DEBUG_TEXT)));
                        }

                        SecurityToken validatedToken = null;
                        ClaimsPrincipal principal = null;

                        try
                        {
                            principal = handler.ValidateToken(idToken, validationParameters, out validatedToken);
                        }
                        catch (SecurityTokenValidationException stvEx)
                        {
                            ExceptionLogService.LogException(new Exception($"Token validation failed: {stvEx.Message}", stvEx));
                        }
                        catch (Exception ex)
                        {
                            ExceptionLogService.LogException(ex, HttpContext.Current);
                        }

                        if (debugModeEnabled)
                        {
                            if (principal != null)
                            {
                                foreach (var claim in principal.Claims)
                                {
                                    ExceptionLogService.LogException(
                                        new Exception($"Claim: {claim.Type} = {claim.Value}")
                                    );
                                }
                            }
                            else
                            {
                                ExceptionLogService.LogException(
                                    new Exception("Principal is null after token validation.")
                                );
                            }
                        }

                        string email = principal.Claims.FirstOrDefault(c => c.Type == "email")?.Value
                               ?? principal.Claims.FirstOrDefault(c => c.Type == "emails")?.Value
                               ?? principal.Claims.FirstOrDefault(c => c.Type == "signInNames.emailAddress")?.Value
                               ?? principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

                        string givenName = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value;
                        string surname = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value;

                        var b2cUser = new B2C_User
                        {
                            id = principal.Claims.FirstOrDefault(c => c.Type == "oid")?.Value,
                            givenName = givenName,
                            surname = surname,
                            userPrincipalName = email,
                            displayName = $"{givenName} {surname}"
                        };

                        string userKey = email != null ? email.ToLowerInvariant() : Guid.NewGuid().ToString();
                        username = $"EntraB2C_{userKey}";

                        if (debugModeEnabled)
                        {
                            var exceptionText = string.Format("UserName: {0}", username);
                            ExceptionLogService.LogException(new Exception(exceptionText, new Exception(EXCEPTION_DEBUG_TEXT)));
                        }
                    }
                }
            }
            catch (SecurityTokenValidationException stvEx)
            {
                ExceptionLogService.LogException(new Exception($"Token validation failed: {stvEx.Message}", stvEx));
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
                restRequest.AddParameter("scope", "openid profile email");

                var restResponse = restClient.Execute(restRequest);

                if (debugModeEnabled)
                {
                    ExceptionLogService.LogException(new Exception($"Token Response: {restResponse.Content}", new Exception(EXCEPTION_DEBUG_TEXT)));
                }

                if (restResponse.StatusCode == HttpStatusCode.OK)
                {
                    // Parse the token response
                    var tokenResponse = JsonConvert.DeserializeObject<B2C_AccessTokenResponse>(restResponse.Content);
                    string idToken = tokenResponse.id_token;

                    if (!string.IsNullOrWhiteSpace(idToken))
                    {
                        var handler = new JwtSecurityTokenHandler();

                        // Retrieve the OpenID Connect metadata document
                        string wellKnownUri = GetAttributeValue("WellKnown");
                        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                            wellKnownUri,
                            new OpenIdConnectConfigurationRetriever());

                        OpenIdConnectConfiguration openIdConfig = null;
                        try
                        {
                            openIdConfig = configurationManager.GetConfigurationAsync().Result;
                        }
                        catch (Exception ex)
                        {
                            ExceptionLogService.LogException(new Exception("Failed to retrieve OpenID configuration", ex));
                            throw;
                        }


                        var validationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidIssuer = openIdConfig.Issuer,
                            ValidateAudience = true,
                            ValidAudience = GetAttributeValue("ClientId"),
                            ValidateLifetime = true,
                            IssuerSigningKeys = openIdConfig.SigningKeys,
                            // Optional: Validate the token's nonce, if used
                        };

                        if (debugModeEnabled)
                        {
                            ExceptionLogService.LogException(new Exception($"Validation Parameters: Issuer={validationParameters.ValidIssuer}, Audience={validationParameters.ValidAudience}", new Exception(EXCEPTION_DEBUG_TEXT)));
                        }

                        SecurityToken validatedToken = null;
                        ClaimsPrincipal principal = null;

                        try
                        {
                            principal = handler.ValidateToken(idToken, validationParameters, out validatedToken);
                        }
                        catch (SecurityTokenValidationException stvEx)
                        {
                            ExceptionLogService.LogException(new Exception($"Token validation failed: {stvEx.Message}", stvEx));
                        }
                        catch (Exception ex)
                        {
                            ExceptionLogService.LogException(ex, HttpContext.Current);
                        }

                        if (debugModeEnabled)
                        {
                            if (principal != null)
                            {
                                foreach (var claim in principal.Claims)
                                {
                                    ExceptionLogService.LogException(
                                        new Exception($"Claim: {claim.Type} = {claim.Value}")
                                    );
                                }
                            }
                            else
                            {
                                ExceptionLogService.LogException(
                                    new Exception("Principal is null after token validation.")
                                );
                            }
                        }

                        // Extract claims from the validated token
                        string email = principal.Claims.FirstOrDefault(c => c.Type == "email")?.Value
                             ?? principal.Claims.FirstOrDefault(c => c.Type == "emails")?.Value
                             ?? principal.Claims.FirstOrDefault(c => c.Type == "signInNames.emailAddress")?.Value
                             ?? principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
                        string givenName = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value;
                        string surname = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value;

                        // Construct a unique username identifier for the local system
                        string userKey = email != null ? email.ToLowerInvariant() : Guid.NewGuid().ToString();
                        var b2cUser = new B2C_User
                        {
                            id = principal.Claims.FirstOrDefault(c => c.Type == "oid")?.Value,
                            givenName = givenName,
                            surname = surname,
                            userPrincipalName = email,
                            displayName = $"{givenName} {surname}"
                        };

                        if (debugModeEnabled)
                        {
                            ExceptionLogService.LogException(new Exception($"B2C_User: ID={b2cUser.id}, GivenName={b2cUser.givenName}, Surname={b2cUser.surname}, UPN={b2cUser.userPrincipalName}, DisplayName={b2cUser.displayName}"));
                        }

                        result.UserName = GetB2CUser(b2cUser, idToken);
                        result.IsAuthenticated = !string.IsNullOrWhiteSpace(result.UserName);

                        if (debugModeEnabled)
                        {
                            ExceptionLogService.LogException(new Exception($"UserName: {result.UserName}", new Exception(EXCEPTION_DEBUG_TEXT)));
                        }
                    }
                }
            }
            catch (SecurityTokenValidationException stvEx)
            {
                ExceptionLogService.LogException(new Exception($"Token validation failed: {stvEx.Message}", stvEx));
            }
            catch (Exception ex)
            {
                ExceptionLogService.LogException(ex, HttpContext.Current);
            }

            return result;
        }

        public override string ImageUrl()
        {
            return string.Empty;
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
            public string id_token { get; set; }
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
        }

        #endregion
    }
}
