using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using bluenumberis.Admin.EntityFramework.Shared.DbContexts;
using bluenumberis.Admin.EntityFramework.Shared.Entities.Identity;
using bluenumberis.Admin.Helpers;
using bluenumberis.Admin.Middlewares;

namespace bluenumberis.Admin.Configuration.Test
{
    public class StartupTest : Startup
    {
        public StartupTest(IWebHostEnvironment env, IConfiguration configuration) : base(env, configuration)
        {
        }

        public override void RegisterDbContexts(IServiceCollection services)
        {
            services.RegisterDbContextsStaging<AdminIdentityDbContext, IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, AdminLogDbContext, AdminAuditLogDbContext>();
        }

        public override void RegisterAuthentication(IServiceCollection services)
        {
            services.AddAuthenticationServicesStaging<AdminIdentityDbContext, UserIdentity, UserIdentityRole>();
        }

        public override void RegisterAuthorization(IServiceCollection services)
        {
            var rootConfiguration = CreateRootConfiguration();
            services.AddAuthorizationPolicies(rootConfiguration);
        }

        public override void UseAuthentication(IApplicationBuilder app)
        {
            app.UseAuthentication();
            app.UseMiddleware<AuthenticatedTestRequestMiddleware>();
        }
    }
}






