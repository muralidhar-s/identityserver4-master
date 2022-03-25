namespace bluenumberis.STS.Identity.ViewModels.Account
{
    public class VerifyOtpResponse
    {
        public string message { get; set; }
        public OtpResponseResult result { get; set; }
    }

    public class OtpResponseResult
    {
        public bool success { get; set; }
        public string message { get; set; }
    }
}