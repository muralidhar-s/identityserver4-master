// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

// Original file: https://github.com/IdentityServer/IdentityServer4.Quickstart.UI
// Modified by Jan �koruba

using System;
using System.Collections.Generic;
using System.Linq;
using bluenumberis.STS.Identity.Configuration;

namespace bluenumberis.STS.Identity.ViewModels.Account
{
    public class LoginViewModel : LoginInputModel
    {
        public bool AllowRememberLogin { get; set; } = true;
        public bool EnableLocalLogin { get; set; } = true;
        public LoginResolutionPolicy LoginResolutionPolicy { get; set; } = LoginResolutionPolicy.PhoneNumber;

        public IEnumerable<ExternalProvider> ExternalProviders { get; set; } = Enumerable.Empty<ExternalProvider>();
        public IEnumerable<ExternalProvider> VisibleExternalProviders => ExternalProviders.Where(x => !String.IsNullOrWhiteSpace(x.DisplayName));

        public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders?.Count() == 1;
        public string ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;

        public String[] CountryCodeList { get; set; }
        public IEnumerable<Microsoft.AspNetCore.Mvc.Rendering.SelectListItem> countryList { get; set; } = new List<Microsoft.AspNetCore.Mvc.Rendering.SelectListItem>();
        public bool IsResendRegOtp { get; set; } = false;
    }
}





