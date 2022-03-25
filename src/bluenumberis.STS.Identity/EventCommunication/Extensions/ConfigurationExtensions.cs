using Amazon;
using bluenumberis.STS.Identity.EventCommunication.Models;
using Microsoft.Extensions.Configuration;
using System;

namespace bluenumberis.STS.Identity.EventCommunication.Extensions
{
    public static class ConfigurationExtensions
    {
        private static string AwsOptionsKey = "AwsOptions";
        public static AwsOptions GetAWSOptions(this IConfiguration configuration)
        {
            return new AwsOptions()
            {
                Region = RegionEndpoint.GetBySystemName(configuration[AwsOptionsKey + ":Region"]),
                AccessKey = configuration[AwsOptionsKey + ":AccessKey"],
                SecretKey = configuration[AwsOptionsKey + ":SecretKey"],
                PublishFailureReAttempts = Convert.ToInt32(configuration[AwsOptionsKey + ":PublishFailureReAttempts"]),
                MessageRetentionSeconds = Convert.ToInt32(configuration[AwsOptionsKey + ":MessageRetentionSeconds"]),
                BNIdentityCreationQueue = configuration[AwsOptionsKey + ":BNIdentityCreationQueue"],
                BNIdentityUpdationQueue = configuration[AwsOptionsKey + ":BNIdentityUpdationQueue"]
            };
        }
    }
}
