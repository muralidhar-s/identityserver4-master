using System.Collections.Generic;

namespace bluenumberis.STS.Identity.ViewModels.Account
{
    public class CountryCode
    {
        public string Name { get; set; }
        public string Flag { get; set; }
        public string Number { get; set; }
        public string Code { get; set; }
    }

    public class CountriesList
    {
        public List<CountryCode> CountryCodes { get; set; }
    }
}