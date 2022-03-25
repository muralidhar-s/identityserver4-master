using Amazon;

namespace bluenumberis.STS.Identity.EventCommunication.Models
{
    public class AwsOptions
    {
        public RegionEndpoint Region { get; set; }
        public string AccessKey { get; set; }
        public string SecretKey { get; set; }
        public int PublishFailureReAttempts { get; set; }
        public int MessageRetentionSeconds { get; set; }
        public string BNIdentityCreationQueue { get; set; }
        public string BNIdentityUpdationQueue { get; set; }
    }
}
