// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

// Original file: https://github.com/IdentityServer/IdentityServer4.Quickstart.UI
// Modified by Jan �koruba

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace bluenumberis.STS.Identity.ViewModels.Account
{
    public class LoginInputModel
    {
        [Required]
        public string PhoneNumber { get; set; }
        public bool IsPhoneNumber { get; set; } = false;
        // [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }

        public string ReferenceId { get; set; }
        public int CountryIndex { get; set; }
        public string CountryCode { get; set; }
        public string CountryNum { get; set; }
        public List<CountryCode> CountryCodes { get; set; }
        public string BlueNumber { get; set; }
        public string TenantId { get; set; }
        public bool IsUserExists { get; set; }
        public bool IsResendOtp { get; set; }
        public bool IsHumanIdLogin { get; set; }
        public string HumanIdExchangeToken { get; set; }
        public string UserAppId { get; set; }

        public int ResendOtpClickCount { get; set; }

        public string Otp1 { get; set; }
        public string Otp2 { get; set; }
        public string Otp3 { get; set; }
        public string Otp4 { get; set; }
        public bool IsWrongOtp { get; set; }

        public string ErrorMessage { get; set; }
    }
}