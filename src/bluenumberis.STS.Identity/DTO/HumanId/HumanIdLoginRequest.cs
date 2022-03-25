namespace bluenumberis.STS.Identity.DTO.HumanId
{
    public class HumanIdLoginRequest
    {
        public string countryCode { get; set; }
        public string phone { get; set; }
        public int deviceTypeId { get; set; }
        public string deviceId { get; set; }
        public string verificationCode { get; set; }
        public string notifId { get; set; }
    }
}
