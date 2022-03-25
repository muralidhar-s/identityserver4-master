namespace bluenumberis.STS.Identity.Configuration.Interfaces
{
    public interface IRootConfiguration
    {
        string BaseUrl { get; }

        AdminConfiguration AdminConfiguration { get; }

        RegisterConfiguration RegisterConfiguration { get; }
    }
}





