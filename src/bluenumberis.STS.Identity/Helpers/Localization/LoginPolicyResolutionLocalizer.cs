using bluenumberis.STS.Identity.Configuration;

namespace bluenumberis.STS.Identity.Helpers.Localization
{
    public static class LoginPolicyResolutionLocalizer
    {
        public static string GetUserNameLocalizationKey(LoginResolutionPolicy policy)
        {
            switch (policy)
            {
                case LoginResolutionPolicy.PhoneNumber:
                    return "Mobile Number";
                //case LoginResolutionPolicy.Email:
                //    return "Email";
                default:
                    return "Mobile Number";
            }
        }
    }
}






