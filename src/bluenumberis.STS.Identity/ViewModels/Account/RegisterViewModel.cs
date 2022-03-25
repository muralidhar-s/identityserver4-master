using System.ComponentModel.DataAnnotations;
using System;
using System.Collections.Generic;
using System.Linq;
using bluenumberis.STS.Identity.Configuration;

namespace bluenumberis.STS.Identity.ViewModels.Account
{
    public class RegisterViewModel
    {
        public string UserName { get; set; }

        [EmailAddress]
        public string Email { get; set; }

        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password")]
        public string ConfirmPassword { get; set; }

        public string PhoneNumber { get; set; }
        public string BlueNumber { get; set; }
        public string TenantId { get; set; }

        public string ReturnUrl { get; set; }
        public bool IsPhoneNumber { get; set; } = false;
        public string referenceId { get; set; }
        public string CountryNum { get; set; }
        public bool isUserExists { get; set; }
        public bool IsResendRegOtp { get; set; } = false;
        public LoginResolutionPolicy LoginResolutionPolicy { get; set; } = LoginResolutionPolicy.PhoneNumber;
        public IEnumerable<Microsoft.AspNetCore.Mvc.Rendering.SelectListItem> countryList { get; set; } = new List<Microsoft.AspNetCore.Mvc.Rendering.SelectListItem>();
    }
}





