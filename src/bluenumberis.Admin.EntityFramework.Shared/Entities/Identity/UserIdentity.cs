using Microsoft.AspNetCore.Identity;

namespace bluenumberis.Admin.EntityFramework.Shared.Entities.Identity
{
	public class UserIdentity : IdentityUser
	{
		public string BlueNumber { get; set; }
		public string TenantId { get; set; }
	}
}





