using Amazon.Runtime;
using bluenumberis.Admin.EntityFramework.Shared.Entities.Identity;
using bluenumberis.STS.Identity.Contracts;
using bluenumberis.STS.Identity.EventCommunication.Extensions;
using bluenumberis.STS.Identity.EventCommunication.Handlers;
using bluenumberis.STS.Identity.EventCommunication.Models;
using JustSaying;
using JustSaying.AwsTools;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace bluenumberis.STS.Identity.Infrastructure.Installers
{
    internal class RegisterAWSEvents : IServiceRegistration
    {
        public void RegisterAppServices(IServiceCollection services, IConfiguration config)
        {
            var awsOptions = config.GetAWSOptions();
            CreateMeABus.DefaultClientFactory = () => new DefaultAwsClientFactory(new BasicAWSCredentials(awsOptions.AccessKey, awsOptions.SecretKey));

            var builder = services.BuildServiceProvider();
            var userManager = (UserManager<UserIdentity>)builder.GetService(typeof(UserManager<UserIdentity>));

            ILoggerFactory loggerFactory = NullLoggerFactory.Instance;
            CreateMeABus.WithLogging(loggerFactory)
                .InRegion(awsOptions.Region.SystemName)
                .WithSqsPointToPointSubscriber()
                .IntoQueue(awsOptions.BNIdentityCreationQueue)
                .ConfigureSubscriptionWith(c => { c.MessageRetentionSeconds = awsOptions.MessageRetentionSeconds; })
                .WithMessageHandler(new BlueNumberCreationHandler(userManager))
                .StartListening();

            CreateMeABus.WithLogging(loggerFactory)
                .InRegion(awsOptions.Region.SystemName)
                .WithSqsPointToPointSubscriber()
                .IntoQueue(awsOptions.BNIdentityUpdationQueue)
                .ConfigureSubscriptionWith(c => { c.MessageRetentionSeconds = awsOptions.MessageRetentionSeconds; })
                .WithMessageHandler(new BlueNumberUpdationHandler(userManager))
                .StartListening();
        }
    }
}