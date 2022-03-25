using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace bluenumberis.STS.Identity.ViewModels.Account
{
    public class ErrorViewModel
    {
        public string PostLogoutRedirectUri { get; set; }
        public string ClientName { get; set; }
        public string ReturnUrl { get; set; }

        public bool AutomaticRedirect { get; set; } = false;
        public bool RedirectFromErrorPage { get; set; } = false;        
    }
}
