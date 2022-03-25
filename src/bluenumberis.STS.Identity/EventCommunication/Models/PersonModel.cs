using System;

namespace bluenumberis.STS.Identity.EventCommunication.Models
{
    public class PersonModel
    {
        public string Name { get; set; }
        public string Gender { get; set; }
        public string Contact { get; set; }
        public string Address { get; set; }
        public decimal? Longitude { get; set; }
        public decimal? Latitude { get; set; }
        public string Role { get; set; }
        public string BlueNumber { get; set; }
        public string Issuer { get; set; }
        public string CreatedBy { get; set; }
        public DateTime CreatedDate { get; set; }
        public string UpdatedBy { get; set; }
        public DateTime UpdatedDate { get; set; }
    }
}