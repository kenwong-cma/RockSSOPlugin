// <copyright>
// Copyright by the Spark Development Network
//
// Licensed under the Rock Community License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.rockrms.com/license
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// </copyright>
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.Net;
using System.Web;
using System.Web.Security;

using Newtonsoft.Json;

using RestSharp;

using Rock.Attribute;
using Rock.Data;
using Rock.Model;
using Rock.Security.Authentication;
using Rock.Security.Authentication.ExternalRedirectAuthentication;
using Rock.Web.Cache;

namespace Rock.Security.ExternalAuthentication
{
    /// <summary>
    /// Authenticates a user using ECD (Entra)
    /// </summary>
    /// <seealso cref="Rock.Security.AuthenticationComponent" />
    [Description("NMC Entra Authentication Provider")]
    [Export(typeof(AuthenticationComponent))]
    [ExportMetadata("ComponentName", "NMC Entra")]

    [TextField("Client ID", "The Entra Client ID")]
    [TextField("Tenant ID", "The Entra Tenant ID")]
    [TextField("Client Secret", "The Entra Client Secret")]

    [Rock.SystemGuid.EntityTypeGuid("FD2B4733-83F1-4283-ADC4-444D744D6100")]
    public class NMCEntra : AuthenticationComponent, IExternalRedirectAuthentication
    {
        /// <summary>
        /// Gets the type of the service.
        /// </summary>
        /// <value>
        /// The type of the service.
        /// </value>
        public override AuthenticationServiceType ServiceType
        {
            get { return AuthenticationServiceType.External; }
        }

        /// <summary>
        /// Determines if user is directed to another site (i.e. Facebook, Gmail, Twitter, etc) to confirm approval of using
        /// that site's credentials for authentication.
        /// </summary>
        /// <value>
        /// The requires remote authentication.
        /// </value>
        public override bool RequiresRemoteAuthentication
        {
            get { return true; }
        }

        /// <summary>
        /// Tests the Http Request to determine if authentication should be tested by this
        /// authentication provider.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        public override bool IsReturningFromAuthentication(HttpRequest request)
        {
            return IsReturningFromExternalAuthentication(request.QueryString.ToSimpleQueryStringDictionary());
        }

        /// <summary>
        /// Generates the log in URL.
        /// </summary>
        /// <param name="request">Forming the URL to obtain user consent</param>
        /// <returns></returns>
        public override Uri GenerateLoginUrl(HttpRequest request)
        {
            string clientId = GetAttributeValue("ClientID");
            string tenantId = GetAttributeValue("TenantID");
            string redirectUri = GetRedirectUrl(request); // Ensure this matches your Azure registered redirect URI
            string returnUrl = request.QueryString["returnurl"];

            string newUrl = string.Format(
                "https://login.microsoftonline.com/{0}/oauth2/v2.0/authorize?response_type=code&client_id={1}&redirect_uri={2}&state={3}&scope=openid profile email User.Read",
                tenantId,
                clientId,
                HttpUtility.UrlEncode(redirectUri),
                HttpUtility.UrlEncode(returnUrl ?? FormsAuthentication.DefaultUrl)
            );

            return new Uri(newUrl);
        }


        /// <summary>
        /// JSON Class for Access Token Response
        /// </summary>
        public class AccessTokenResponse
        {
            /// <summary>
            /// Gets or sets the access_token.
            /// </summary>
            /// <value>
            /// The access_token.
            /// </value>
            public string access_token { get; set; }

            /// <summary>
            /// Gets or sets the expires_in.
            /// </summary>
            /// <value>
            /// The expires_in.
            /// </value>
            public int expires_in { get; set; }

            /// <summary>
            /// Gets or sets the token_type.
            /// </summary>
            /// <value>
            /// The token_type.
            /// </value>
            public string token_type { get; set; }
        }

        /// <inheritdoc/>
        public override bool Authenticate(HttpRequest request, out string userName, out string returnUrl)
        {
            var options = new ExternalRedirectAuthenticationOptions
            {
                RedirectUrl = GetRedirectUrl(request),
                Parameters = request.QueryString.ToSimpleQueryStringDictionary()
            };

            var result = Authenticate(options);

            userName = result.UserName;
            returnUrl = result.ReturnUrl;

            return result.IsAuthenticated;
        }

        /// <summary>
        /// Gets the URL of an image that should be displayed.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override string ImageUrl()
        {
            return string.Empty;
        }

        private string GetRedirectUrl(HttpRequest request)
        {
            Uri uri = new Uri(request.UrlProxySafe().ToString());
            return uri.Scheme + "://" + uri.GetComponents(UriComponents.HostAndPort, UriFormat.UriEscaped) + uri.LocalPath;
        }

        /// <summary>
        /// Authenticates the user based on user name and password
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override bool Authenticate(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Encodes the password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override string EncodePassword(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets a value indicating whether [supports change password].
        /// </summary>
        /// <value>
        /// <c>true</c> if [supports change password]; otherwise, <c>false</c>.
        /// </value>
        public override bool SupportsChangePassword
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Changes the password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="oldPassword">The old password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="warningMessage">The warning message.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override bool ChangePassword(UserLogin user, string oldPassword, string newPassword, out string warningMessage)
        {
            warningMessage = "not supported";
            return false;
        }

        /// <summary>
        /// Sets the password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="System.NotImplementedException"></exception>
        public override void SetPassword(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Entra User Object
        /// </summary>
        public class EntraUser
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
        /// Gets the name of the Entra user.
        /// </summary>
        /// <param name="entraUser">The Entra user.</param>
        /// <param name="accessToken">The access token.</param>
        /// <returns></returns>
        public static string GetEntraUser(EntraUser entraUser, string accessToken = "")
        {
            if (accessToken.IsNullOrWhiteSpace())
            {
                return null;
            }

            string username = string.Empty;
            string email = entraUser.userPrincipalName;
            string entraId = entraUser.id;

            string userName = "Entra_" + email;
            UserLogin user = null;

            using (var rockContext = new RockContext())
            {
                var userLoginService = new UserLoginService(rockContext);
                user = userLoginService.GetByUserName(userName);

                if (user == null)
                {
                    string lastName = entraUser.surName.ToString();
                    string firstName = entraUser.givenName.ToString();

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

                            if (person != null)
                            {
                                PersonService.SaveNewPerson(person, rockContext, null, false);
                            }
                        }

                        if (person != null)
                        {
                            int typeId = EntityTypeCache.Get(typeof(Entra)).Id;
                            user = UserLoginService.Create(rockContext, person, AuthenticationServiceType.External, typeId, userName, "entra", true);
                        }
                    });
                }

                if (user != null)
                {
                    return user.UserName;
                }

                return username;
            }
        }

        #region IExternalRedirectAuthentication Implementation

        /// <inheritdoc/>
        public ExternalRedirectAuthenticationResult Authenticate(ExternalRedirectAuthenticationOptions options)
        {
            var result = new ExternalRedirectAuthenticationResult
            {
                UserName = string.Empty,
                ReturnUrl = options.Parameters.GetValueOrNull("state")
            };

            try
            {
                string tenantId = GetAttributeValue("TenantID");
                var restClient = new RestClient($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token");
                var restRequest = new RestRequest(Method.POST);
                restRequest.AddParameter("code", options.Parameters.GetValueOrNull("code"));
                restRequest.AddParameter("client_id", GetAttributeValue("ClientID"));
                restRequest.AddParameter("client_secret", GetAttributeValue("ClientSecret"));
                restRequest.AddParameter("redirect_uri", options.RedirectUrl);
                restRequest.AddParameter("grant_type", "authorization_code");
                var restResponse = restClient.Execute(restRequest);

                if (restResponse.StatusCode == HttpStatusCode.OK)
                {
                    var accesstokenresponse = JsonConvert.DeserializeObject<AccessTokenResponse>(restResponse.Content);
                    string accessToken = accesstokenresponse.access_token;

                    restRequest = new RestRequest(Method.GET);
                    restRequest.AddHeader("Authorization", $"Bearer {accessToken}");
                    restClient = new RestClient("https://graph.microsoft.com/v1.0/me");
                    restResponse = restClient.Execute(restRequest);

                    if (restResponse.StatusCode == HttpStatusCode.OK)
                    {
                        EntraUser entraUser = JsonConvert.DeserializeObject<EntraUser>(restResponse.Content);
                        result.UserName = GetEntraUser(entraUser, accessToken);
                        result.IsAuthenticated = !string.IsNullOrWhiteSpace(result.UserName);
                    }
                }
            }
            catch (Exception ex)
            {
                ExceptionLogService.LogException(ex, HttpContext.Current);
            }

            return result;
        }

        /// <inheritdoc/>
        public Uri GenerateExternalLoginUrl(string externalProviderReturnUrl, string successfulAuthenticationRedirectUrl)
        {
            string tenantId = GetAttributeValue("TenantID");
            return new Uri(string.Format(
                "https://login.microsoftonline.com/{0}/oauth2/v2.0/authorize?response_type=code&client_id={1}&redirect_uri={2}&state={3}&scope=openid profile email User.Read",
                tenantId,
                GetAttributeValue("ClientID"),
                HttpUtility.UrlEncode(externalProviderReturnUrl),
                HttpUtility.UrlEncode(successfulAuthenticationRedirectUrl ?? FormsAuthentication.DefaultUrl)));
        }

        /// <inheritdoc/>
        public bool IsReturningFromExternalAuthentication(IDictionary<string, string> parameters)
        {
            return !string.IsNullOrWhiteSpace(parameters.GetValueOrNull("code")) &&
                !string.IsNullOrWhiteSpace(parameters.GetValueOrNull("state"));
        }

        #endregion
    }
}
