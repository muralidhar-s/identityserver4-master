using bluenumberis.Admin.EntityFramework.Shared.Entities.Identity;
using bluenumberis.STS.Identity.EventCommunication.Models;
using JustSaying.Messaging.MessageHandling;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace bluenumberis.STS.Identity.EventCommunication.Handlers
{
    public class BlueNumberUpdationHandler : IHandlerAsync<BNIdentityUpdationMessage>
    {
        #region Private Variables
        private readonly UserManager<UserIdentity> _userManager;
        #endregion

        #region Constructor
        public BlueNumberUpdationHandler(UserManager<UserIdentity> userManager)
        {
            _userManager = userManager;
        }
        #endregion

        #region Public Methods
        public async Task<bool> Handle(BNIdentityUpdationMessage message)
        {
            return await Task.FromResult(true);
        }
        #endregion
    }
}
