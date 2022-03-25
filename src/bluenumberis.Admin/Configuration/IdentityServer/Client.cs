using System.Collections.Generic;
using bluenumberis.Admin.Configuration.Identity;

namespace bluenumberis.Admin.Configuration.IdentityServer
{
    public class Client : global::IdentityServer4.Models.Client
    {
        public List<Claim> ClientClaims { get; set; } = new List<Claim>();
    }
}






