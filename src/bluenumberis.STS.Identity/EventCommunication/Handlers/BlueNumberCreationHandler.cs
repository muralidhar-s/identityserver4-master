using bluenumberis.STS.Identity.EventCommunication.Models;
using bluenumberis.STS.Identity.EventCommunication.Constants.Enums;
using JustSaying.Messaging.MessageHandling;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using bluenumberis.Admin.EntityFramework.Shared.Entities.Identity;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Collections.Generic;
using IdentityModel;
using System;

namespace bluenumberis.STS.Identity.EventCommunication.Handlers
{
    public class BlueNumberCreationHandler : IHandlerAsync<BNIdentityCreationMessage>
    {
        #region Private Variables
        private readonly UserManager<UserIdentity> _userManager;
        #endregion

        #region Constructor
        public BlueNumberCreationHandler(UserManager<UserIdentity> userManager)
        {
            _userManager = userManager;
        }
        #endregion

        #region Public Methods
        public async Task<bool> Handle(BNIdentityCreationMessage message)
        {
            try
            {
                var person = JsonConvert.DeserializeObject<PersonModel>(message.Data);
                var user = new UserIdentity
                {
                    PhoneNumber = person.Contact,
                    BlueNumber = person.BlueNumber,
                    TenantId = person.Issuer,
                    Email = person.BlueNumber + "@bluenumber.org",
                    UserName = person.BlueNumber
                };

                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    var claimsToAdd = new List<Claim>();

                    if (!string.IsNullOrWhiteSpace(user.BlueNumber))
                    {
                        claimsToAdd.Add(new Claim(nameof(user.BlueNumber), user.BlueNumber));
                    }

                    if (!string.IsNullOrWhiteSpace(user.PhoneNumber))
                    {
                        claimsToAdd.Add(new Claim(nameof(user.PhoneNumber), user.PhoneNumber));
                    }

                    if (!string.IsNullOrWhiteSpace(user.TenantId))
                    {
                        claimsToAdd.Add(new Claim(nameof(user.TenantId), user.TenantId));
                    }

                    await _userManager.AddClaimsAsync(user, claimsToAdd);
                }
                else
                {
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
        #endregion
    }
}