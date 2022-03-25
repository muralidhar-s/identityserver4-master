using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using bluenumberis.Admin.EntityFramework.Shared.DbContexts;
using bluenumberis.Admin.EntityFramework.Shared.Entities.Identity;
using bluenumberis.STS.Identity.Configuration;
using bluenumberis.STS.Identity.Configuration.Constants;
using bluenumberis.STS.Identity.Configuration.Interfaces;
using bluenumberis.STS.Identity.Infrastructure.Extensions;
using bluenumberis.STS.Identity.Helpers;
using Microsoft.AspNetCore.HttpOverrides;
using System.Linq;

namespace bluenumberis.STS.Identity
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var rootConfiguration = CreateRootConfiguration();
            services.AddSingleton(rootConfiguration);

            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.All;
                options.AllowedHosts = Configuration.GetValue<string>("AllowedHosts")?.Split(';').ToList<string>();
            });

            // Register DbContexts for IdentityServer and Identity
            RegisterDbContexts(services);

            // Add email senders which is currently setup for SendGrid and SMTP
            services.AddEmailSenders(Configuration);

            // Add services for authentication, including Identity model and external providers
            RegisterAuthentication(services);
            
            // Add all dependencies for Asp.Net Core Identity in MVC - these dependencies are injected into generic Controllers
            // Including settings for MVC and Localization
            // If you want to change primary keys or use another db model for Asp.Net Core Identity:
            services.AddMvcWithLocalization<UserIdentity, string>(Configuration);

            // Add authorization policies for MVC
            RegisterAuthorization(services);

            services.AddIdSHealthChecks<IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, AdminIdentityDbContext>(Configuration);

            services.AddServicesInAssembly(Configuration);
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            string baseUrl = Configuration.GetSection("BaseUrl").Value;
            if (!string.IsNullOrEmpty(baseUrl))
            {
                baseUrl = "/" + baseUrl;
                app.UsePathBase(baseUrl);
            }
            else
            {
                baseUrl = "";
            }

            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Add custom security headers
            app.UseForwardedHeaders();
            app.UseSecurityHeaders();
            app.UseStaticFiles();
            UseAuthentication(app);
            app.UseMvcLocalizationServices();

            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(endpoint => 
            { 
                endpoint.MapDefaultControllerRoute();
                endpoint.MapHealthChecks(baseUrl + "/health", new HealthCheckOptions
                {
                    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
                });
            });
        }

        public virtual void RegisterDbContexts(IServiceCollection services)
        {
            services.RegisterDbContexts<AdminIdentityDbContext, IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext>(Configuration);
        }

        public virtual void RegisterAuthentication(IServiceCollection services)
        {
            services.AddAuthenticationServices<AdminIdentityDbContext, UserIdentity, UserIdentityRole>(Configuration);
            services.AddIdentityServer<IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, UserIdentity>(Configuration);
        }

        public virtual void RegisterAuthorization(IServiceCollection services)
        {
            var rootConfiguration = CreateRootConfiguration();
            services.AddAuthorizationPolicies(rootConfiguration);
        }

        public virtual void UseAuthentication(IApplicationBuilder app)
        {
            app.UseIdentityServer();
        }

        protected IRootConfiguration CreateRootConfiguration()
        {
            var rootConfiguration = new RootConfiguration();
            Configuration.GetSection(ConfigurationConsts.AdminConfigurationKey).Bind(rootConfiguration.AdminConfiguration);
            Configuration.GetSection(ConfigurationConsts.RegisterConfigurationKey).Bind(rootConfiguration.RegisterConfiguration);
            return rootConfiguration;
        }
    }
}






