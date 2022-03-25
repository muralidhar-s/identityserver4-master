using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using bluenumberis.STS.Identity.ViewModels.Account;
using bluenumberis.Admin.EntityFramework.Shared.Entities.Identity;
using System.Security.Claims;
using System.Collections.Generic;

namespace bluenumberis.STS.Identity.Controllers
{
//    [Authorize]
    [Route("api/[controller]")]
    public class ApiServiceController<TUser, TKey> : ControllerBase
           where TUser : UserIdentity, new()
           where TKey : IEquatable<TKey>
    {
        private readonly UserManager<TUser> _userManager;

        public ApiServiceController(UserManager<TUser> userManager)
            {
            _userManager = userManager;
        }
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var user = new TUser
             {
                PhoneNumber = model.PhoneNumber,
                BlueNumber = model.BlueNumber,
                TenantId = model.TenantId
            };

            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                var claimsToAdd = new List<Claim>();

                if (!string.IsNullOrWhiteSpace(user.BlueNumber))
                {
                    claimsToAdd.Add(new Claim(nameof(user.BlueNumber), user.BlueNumber));
                }

                if(!string.IsNullOrWhiteSpace(user.PhoneNumber))
                {
                    claimsToAdd.Add(new Claim(nameof(user.PhoneNumber), user.PhoneNumber));
                }

                if(!string.IsNullOrWhiteSpace(user.TenantId))
                {
                    claimsToAdd.Add(new Claim(nameof(user.TenantId), user.TenantId));
                }

                await _userManager.AddClaimsAsync(user, claimsToAdd);
                return Ok(user);
            }

            AddErrors(result);

            // If we got this far, something failed, redisplay form
            return BadRequest(ModelState);
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
   }
}