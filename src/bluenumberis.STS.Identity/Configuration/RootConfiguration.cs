using bluenumberis.STS.Identity.Configuration.Interfaces;

namespace bluenumberis.STS.Identity.Configuration
{
    public class RootConfiguration : IRootConfiguration
    {
        public string BaseUrl { get; } = string.Empty;
        public AdminConfiguration AdminConfiguration { get; } = new AdminConfiguration();
        public RegisterConfiguration RegisterConfiguration { get; } = new RegisterConfiguration();
    }
}





