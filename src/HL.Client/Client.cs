using HL.Client.Authentication;
using HL.Client.Operations;
using System;
using System.Threading.Tasks;

namespace HL.Client
{
    /// <summary>
    /// Defines the base client.
    /// </summary>
    public class Client
    {
        #region Constants
        private const string CookieName = "HLWEBsession";
        #endregion

        #region Fields
        private Requestor _requestor;
        #endregion

        #region Authentication
        /// <summary>
        /// Authenticate the client.
        /// </summary>
        /// <param name="username">Your username.</param>
        /// <param name="password">Your password.</param>
        /// <param name="birthday">Your birthday.</param>
        /// <param name="securityNumbe">Your security number.</param>
        /// <returns></returns>
        public async Task<bool> AuthenticateAsync(string username, string password, DateTime birthday, string securityNumbe)
        {
            // Start stage 1
            Stage1 s1 = new Stage1(_requestor,
                                    username,
                                    birthday);

            // Run stage 1
            await s1.RunAsync().ConfigureAwait(false);

            // Start stage 2
            Stage2 s2 = new Stage2(_requestor,
                                    password,
                                    securityNumbe);

            // Run stage 2
            await s2.RunAsync().ConfigureAwait(false);

            return await IsAuthenticated();
        }

        /// <summary>
        /// Check whether the client is still authenticated.
        /// </summary>
        public async Task<bool> IsAuthenticated()
        {
            var response = await _requestor.GetAsync("my-accounts/portfolio_overview");
            return !response.RequestMessage?.RequestUri?.ToString().Contains("login") ?? false;
        }
        #endregion

        #region Operations
        /// <summary>
        /// Gets the account operations.
        /// </summary>
        public virtual AccountOperations AccountOperations { get; set; }

        /// <summary>
        /// Gets or sets the message operations.
        /// </summary>
        public virtual MessageOperations MessageOperations { get; set; }

        /// <summary>
        /// Gets or sets the linked account operations.
        /// </summary>
        public virtual LinkedAccountOperations LinkedAccountOperations { get; set; }
        #endregion

        #region Constructor
        public Client(Requestor requestor = null)
        {
            // Load the requestor
            _requestor = requestor ?? new Requestor();

            // Setup the operations 
            AccountOperations = new AccountOperations(_requestor);
            MessageOperations = new MessageOperations(_requestor);
            LinkedAccountOperations = new LinkedAccountOperations(_requestor);
        }
        #endregion
    }
}
