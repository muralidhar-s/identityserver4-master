namespace bluenumberis.STS.Identity.DTO.Issuer
{
    public class LoginOTPRequest
    {
        public string Mobile { get; set; }
        public string Otp { get; set; }
        public string ReferenceId { get; set; }
    }
}
