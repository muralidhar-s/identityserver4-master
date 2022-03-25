// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

// Original file: https://github.com/IdentityServer/IdentityServer4.Samples
// Modified by Jan �koruba

using bluenumberis.Admin.EntityFramework.Shared.Entities.Identity;
using bluenumberis.STS.Identity.Configuration;
using bluenumberis.STS.Identity.DTO.HumanId;
using bluenumberis.STS.Identity.DTO.Issuer;
using bluenumberis.STS.Identity.Helpers;
using bluenumberis.STS.Identity.Helpers.Localization;
using bluenumberis.STS.Identity.Services.Abstract;
using bluenumberis.STS.Identity.ViewModels.Account;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Xml;

namespace bluenumberis.STS.Identity.Controllers
{
    [SecurityHeaders]
    [Authorize]
    public class AccountController<TUser, TKey> : Controller
        where TUser : UserIdentity, new()
        where TKey : IEquatable<TKey>
    {
        private readonly UserResolver<TUser> _userResolver;
        private readonly UserManager<TUser> _userManager;
        private readonly SignInManager<TUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly IEmailSender _emailSender;
        private readonly IGenericControllerLocalizer<AccountController<TUser, TKey>> _localizer;
        private readonly LoginConfiguration _loginConfiguration;
        private readonly RegisterConfiguration _registerConfiguration;
        private readonly IHumanIdService _humanIdService;
        private readonly IIssuerService _issuerService;

        private readonly IConfiguration _configuration;

        private bool _isUserExists = false;

        private CountriesList codeListObj;
        public AccountController(
            UserResolver<TUser> userResolver,
            UserManager<TUser> userManager,
            SignInManager<TUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IEmailSender emailSender,
            IHumanIdService humanIdService,
            IIssuerService issuerService,
            IGenericControllerLocalizer<AccountController<TUser, TKey>> localizer,
            LoginConfiguration loginConfiguration,
            RegisterConfiguration registerConfiguration,
            IConfiguration configuration)
        {
            _userResolver = userResolver;
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _emailSender = emailSender;
            _humanIdService = humanIdService;
            _issuerService = issuerService;
            _localizer = localizer;
            _loginConfiguration = loginConfiguration;
            _registerConfiguration = registerConfiguration;
            _configuration = configuration;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (_isUserExists)
                vm.IsUserExists = true;

            if (!string.IsNullOrEmpty(returnUrl) && returnUrl.Contains("IsRegister"))
            {
                throw new Exception("Invalid return url.");
            }

            if (vm.EnableLocalLogin == false && vm.ExternalProviders.Count() == 1)
            {
                // only one option for logging in
                return ExternalLogin(vm.ExternalProviders.First().AuthenticationScheme, returnUrl);
            }

            if (!string.IsNullOrEmpty(vm.CountryCode) && vm.CountryNum.Equals("+1"))
            {
                vm.IsHumanIdLogin = true;
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (model == null)
            {
                throw new Exception("Invalid model.");
            }

            var json = System.IO.File.ReadAllText("country-codes.json");
            model.CountryCodes = JsonConvert.DeserializeObject<CountriesList>(json).CountryCodes;
            model.CountryNum = model.CountryCodes.Where(c => c.Code == model.CountryCode).First().Number;
            if ((button == "login" || button == "resendotp") && model.PhoneNumber != null && model.Password == null)
            {
                try
                {
                    if (model.CountryNum.Equals("+1") || model.CountryCode.Equals("US"))
                    {
                        model.IsHumanIdLogin = true;
                    }
                    else
                    {
                        model.IsHumanIdLogin = false;
                        if (model != null)
                        {
                            model.Password = model.Otp1 + model.Otp2 + model.Otp3 + model.Otp4;
                        }
                        var user = (TUser)await _userManager.Users.SingleOrDefaultAsync(x => x.PhoneNumber == model.CountryNum + model.PhoneNumber);
                        if (user == null)
                        {
                            model.IsUserExists = false;
                        }
                        else
                        {
                            model.IsUserExists = true;
                        }
                    }

                    if (model.ResendOtpClickCount == 0 || model.ResendOtpClickCount < 2)
                    {
                        var viewModel = await GenerateOTP(model, button);
                        return View(viewModel);
                    }
                    else
                    {
                        var vModel = await BuildLoginViewModelAsync(model);
                        return View(vModel);
                    }

                    // var viewModel = await GenerateOTP(model, button);
                    // return View(viewModel);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }

            if (ModelState.IsValid && button != "tryanotherno")
            {
                model.Password = model.Otp1 + model.Otp2 + model.Otp3 + model.Otp4;
                if (model.Password == null || model.Password == "")
                {
                    var vm1 = await BuildLoginViewModelAsync(model);
                    vm1.IsPhoneNumber = true;
                    return View(vm1);
                }
                try
                {
                    return await ValidateOTP(context, model, button);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }

            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("Error");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
                {
                    ModelState.AddModelError(string.Empty, _localizer["EmailNotFound"]);

                    return View(model);
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code }, HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, _localizer["ResetPasswordTitle"], _localizer["ResetPasswordBody", HtmlEncoder.Default.Encode(callbackUrl)]);


                return View("ForgotPasswordConfirmation");
            }

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(ResetPasswordConfirmation), "Account");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation), "Account");
            }

            AddErrors(result);

            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, _localizer["ErrorExternalProvider", remoteError]);

                return View(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (result.Succeeded)
            {
                return RedirectToLocal(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(LoginWith2fa), new { ReturnUrl = returnUrl });
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }

            // If the user does not have an account, then ask the user to create an account.
            ViewData["ReturnUrl"] = returnUrl;
            ViewData["LoginProvider"] = info.LoginProvider;
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);

            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });
        }

        [HttpPost]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return Challenge(properties, provider);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            // Get the information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return View("ExternalLoginFailure");
            }

            if (ModelState.IsValid)
            {
                var user = new TUser
                {
                    UserName = model.UserName,
                    Email = model.Email
                };

                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);

                        return RedirectToLocal(returnUrl);
                    }
                }

                AddErrors(result);
            }

            ViewData["LoginProvider"] = info.LoginProvider;
            ViewData["ReturnUrl"] = returnUrl;

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWithRecoveryCode(string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException(_localizer["Unable2FA"]);
            }

            var model = new LoginWithRecoveryCodeViewModel()
            {
                ReturnUrl = returnUrl
            };

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException(_localizer["Unable2FA"]);
            }

            var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                return LocalRedirect(string.IsNullOrEmpty(model.ReturnUrl) ? "~/" : model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                return View("Lockout");
            }

            ModelState.AddModelError(string.Empty, _localizer["InvalidRecoveryCode"]);

            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2fa(bool rememberMe, string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new InvalidOperationException(_localizer["Unable2FA"]);
            }

            var model = new LoginWith2faViewModel()
            {
                ReturnUrl = returnUrl,
                RememberMe = rememberMe
            };

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException(_localizer["Unable2FA"]);
            }

            var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, model.RememberMe, model.RememberMachine);

            if (result.Succeeded)
            {
                return LocalRedirect(string.IsNullOrEmpty(model.ReturnUrl) ? "~/" : model.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                return View("Lockout");
            }

            ModelState.AddModelError(string.Empty, _localizer["InvalidAuthenticatorCode"]);

            return View(model);
        }

        [HttpPost]
        public IActionResult SetLanguage(string culture, string returnUrl)
        {
            Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1) }
            );
            return LocalRedirect(returnUrl);
        }

        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            var json = System.IO.File.ReadAllText("country-codes.json");
            codeListObj = JsonConvert.DeserializeObject<CountriesList>(json);

            var countryListtemp = new List<SelectListItem>();

            string countryCode = string.Empty;
            if (!string.IsNullOrEmpty(returnUrl) && returnUrl.Contains("ccode"))
            {
                countryCode = returnUrl.Substring(returnUrl.IndexOf("ccode") + 6, 2);
            }
            
            string countryNo = "";
            int countryIndex = 0;
            if (!string.IsNullOrEmpty(countryCode))
            {
                var country = codeListObj.CountryCodes.Where(c => c.Code == countryCode).FirstOrDefault();
                if (country != null)
                {
                    countryNo = country.Number;
                    countryIndex = codeListObj.CountryCodes.IndexOf(country);
                }
            }
            
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    PhoneNumber = context?.LoginHint,
                    LoginResolutionPolicy = _loginConfiguration.ResolutionPolicy,
                    ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } },
                    countryList = countryListtemp,
                    CountryNum = countryNo
                };
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                PhoneNumber = context?.LoginHint,
                LoginResolutionPolicy = _loginConfiguration.ResolutionPolicy,
                ExternalProviders = providers.ToArray(),
                IsPhoneNumber = AccountOptions.IsPhoneNumber,
                CountryCodes = codeListObj.CountryCodes,
                CountryIndex = countryIndex,
                CountryCode = countryCode,
                CountryNum = countryNo
            };
        }

        private ErrorViewModel BuildErrorViewModel(String ReturnUrl)
        {
            var vm = new ErrorViewModel
            {
                AutomaticRedirect = AccountOptions.RedirectFromErrorPage,
                ReturnUrl = ReturnUrl
            };

            return vm;
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.IsPhoneNumber = model.IsPhoneNumber;
            vm.IsHumanIdLogin = model.IsHumanIdLogin;
            if (vm.CountryCode != model.CountryCode)
            {
                model.CountryIndex = model.CountryCodes.IndexOf(model.CountryCodes.Where(c => c.Code == model.CountryCode).FirstOrDefault());
            }
             vm.CountryIndex = model.CountryIndex;
            vm.CountryCode = model.CountryCode;
            vm.CountryNum = model.CountryNum;
            vm.PhoneNumber = model.PhoneNumber;
            vm.RememberLogin = model.RememberLogin;
            vm.ReferenceId = model.ReferenceId;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        private async Task<LoginViewModel> GenerateOTP(LoginInputModel model, string button)
        {
            bool otpSent = false;
            if (model.IsHumanIdLogin)
            {
                var response = await _humanIdService.RequestOTP(model.CountryNum, model.PhoneNumber);
                otpSent = response.success;
            }
            else
            {
                var response = await _issuerService.GetOTP(model.CountryNum, model.PhoneNumber, model.IsUserExists);
                otpSent = response.Result.Success;
                model.ReferenceId = response.Result.ReferenceId;
            }

            var viewModel = await BuildLoginViewModelAsync(model);
            viewModel.IsPhoneNumber = true;
            viewModel.IsUserExists = model.IsUserExists;
            viewModel.ReferenceId = model.ReferenceId;
            if (otpSent)
            {
                if (button == "resendotp")
                {
                    viewModel.IsResendOtp = true;
                    viewModel.ResendOtpClickCount = model.ResendOtpClickCount + 1;
                }
            }
            else
            {
                viewModel.ErrorMessage = "Failed to send otp to phone.";
            }

            return viewModel;
        }

        private async Task<IActionResult> ValidateOTP(AuthorizationRequest context, LoginInputModel model, string button)
        {
            LoginViewModel viewModel = await BuildLoginViewModelAsync(model);
            if (model.IsHumanIdLogin)
            {
                HumanIdLoginRequest dto = new HumanIdLoginRequest()
                {
                    countryCode = model.CountryNum,
                    phone = model.PhoneNumber,
                    deviceTypeId = 1,
                    deviceId = Guid.NewGuid().ToString(),
                    verificationCode = model.Password,
                    notifId = default
                };
                var response = await _humanIdService.Login(dto);
                if (response.success)
                {
                    var humanIdExchangeToken = JsonConvert.DeserializeObject<HumanIdExchangeToken>(JsonConvert.SerializeObject(response.data));
                    model.HumanIdExchangeToken = humanIdExchangeToken.exchangeToken;
                    var tokenExchangeResponse = await _humanIdService.VerifyExchangeToken(humanIdExchangeToken);
                    if (tokenExchangeResponse.success)
                    {
                        model.UserAppId = JsonConvert.DeserializeObject<HumanIdUserAppId>(JsonConvert.SerializeObject(tokenExchangeResponse.data)).appUserId;
                        var user = (TUser)await _userManager.Users.SingleOrDefaultAsync(x => x.PhoneNumber == model.UserAppId);
                        if (user == null)
                        {
                            await RegisterUser(model);
                        }

                        return await SignUser(context, model);
                    }
                    else
                    {
                        viewModel.ErrorMessage = "Failed to get UserAppId from HumanId";
                        return View(viewModel);
                    }
                }
                else
                {
                    viewModel.ErrorMessage = "OTP verification with HumanId is failed.";
                    return View(viewModel);
                }
            }
            else
            {
                if (model.IsUserExists)
                {
                    LoginOTPRequest dto = new LoginOTPRequest()
                    {
                        Mobile = model.CountryNum + model.PhoneNumber,
                        Otp = model.Password,
                        ReferenceId = model.ReferenceId
                    };
                    var respone = await _issuerService.VerifyLoginOTP(dto);
                    if (respone.Result.Success)
                    {
                        return await SignUser(context, model);
                    }
                    else
                    {
                        model.IsWrongOtp = true;
                    }
                }
                else
                {
                    RegisterOTPRequest dto = new RegisterOTPRequest()
                    {
                        Otp = model.Password,
                        ReferenceId = model.ReferenceId
                    };
                    var respone = await _issuerService.VerifyRegisterOTP(dto);
                    if (respone.Result.Success)
                    {
                        await RegisterUser(model);
                        return await SignUser(context, model);
                    }
                    else
                    {
                        model.IsWrongOtp = true;
                    }
                }
            }

            viewModel.ErrorMessage = "Error in OTP verification.";
            return View(viewModel);
        }

        private async Task<IActionResult> SignUser(AuthorizationRequest context, LoginInputModel model)
        {
            string searchKey = model.IsHumanIdLogin ? model.UserAppId : model.CountryNum + model.PhoneNumber;
            var user = (TUser)await _userManager.Users.SingleOrDefaultAsync(x => x.PhoneNumber == searchKey);
            await _signInManager.SignInAsync(user, model.RememberLogin, null);
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.UserName));

            if (context != null)
            {
                if (await _clientStore.IsPkceClientAsync(context.ClientId))
                {
                    // if the client is PKCE then we assume it's native, so this change in how to
                    // return the response is for better UX for the end user.
                    return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                }

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                return Redirect(model.ReturnUrl);
            }

            // request for a local page
            if (Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            if (string.IsNullOrEmpty(model.ReturnUrl))
            {
                return Redirect("~/");
            }

            // user might have clicked on a malicious link - should be logged
            throw new Exception("invalid return URL");
        }

        private async Task RegisterUser(LoginInputModel model)
        {
            RegisterBlueNumberRequest dto = new RegisterBlueNumberRequest()
            {
                Contact = model.IsHumanIdLogin ? model.UserAppId : model.CountryNum + model.PhoneNumber,
                Name = "greenzone-user",
                Address = "default",
                Longitude = 0,
                Latitude = 0,
                Role = "Farmer",
                Gender = "Male",
                ReferenceId = model.IsHumanIdLogin ? "[humanId]" : model.ReferenceId,
                IsHumanId = model.IsHumanIdLogin
            };

            var response = await _issuerService.RegisterPhone(dto);
            if (!response.IsError)
            {
                /* Create User */
                var userNew = new TUser
                {
                    PhoneNumber = model.IsHumanIdLogin ? model.UserAppId : model.CountryNum + model.PhoneNumber,
                    BlueNumber = response.Result.BlueNumber,
                    TenantId = "L1330H1842Y3025O0912",
                    Email = response.Result.BlueNumber + "@bluenumber.org",
                    UserName = response.Result.BlueNumber
                };

                var result = await _userManager.CreateAsync(userNew);
                if (result.Succeeded)
                {
                    var claimsToAdd = new List<Claim>();

                    if (!string.IsNullOrWhiteSpace(userNew.BlueNumber))
                    {
                        claimsToAdd.Add(new Claim(nameof(userNew.BlueNumber), userNew.BlueNumber));
                    }

                    if (!string.IsNullOrWhiteSpace(userNew.PhoneNumber))
                    {
                        claimsToAdd.Add(new Claim(nameof(userNew.PhoneNumber), userNew.PhoneNumber));
                    }

                    if (!string.IsNullOrWhiteSpace(userNew.TenantId))
                    {
                        claimsToAdd.Add(new Claim(nameof(userNew.TenantId), userNew.TenantId));
                    }

                    if (!string.IsNullOrWhiteSpace(userNew.TenantId))
                    {
                        claimsToAdd.Add(new Claim("Issuer", userNew.TenantId));
                    }

                    await _userManager.AddClaimsAsync(userNew, claimsToAdd);
                }
            }
            else
            {
                throw new Exception("Failed to register new user.");
            }
        }
    }
}