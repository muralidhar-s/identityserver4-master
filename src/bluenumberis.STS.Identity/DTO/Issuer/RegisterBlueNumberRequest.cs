namespace bluenumberis.STS.Identity.DTO.Issuer
{
    public class RegisterBlueNumberRequest
    {
        public string Contact { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public double Longitude { get; set; }
        public double Latitude { get; set; }
        public string Role { get; set; }
        public string Gender { get; set; }
        public string ReferenceId { get; set; }
        public bool IsHumanId { get; set; }
    }
}
