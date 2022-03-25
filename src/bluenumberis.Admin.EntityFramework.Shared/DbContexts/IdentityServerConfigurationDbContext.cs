using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;
using Skoruba.IdentityServer4.Admin.EntityFramework.Interfaces;

namespace bluenumberis.Admin.EntityFramework.Shared.DbContexts
{
    public class IdentityServerConfigurationDbContext : ConfigurationDbContext<IdentityServerConfigurationDbContext>, IAdminConfigurationDbContext
    {
        public IdentityServerConfigurationDbContext(DbContextOptions<IdentityServerConfigurationDbContext> options, ConfigurationStoreOptions storeOptions)
            : base(options, storeOptions)
        {
        }

        public DbSet<ApiResourceProperty> ApiResourceProperties { get; set; }

        public DbSet<IdentityResourceProperty> IdentityResourceProperties { get; set; }

        public DbSet<ApiSecret> ApiSecrets { get; set; }

        public DbSet<ApiScope> ApiScopes { get; set; }

        public DbSet<ApiScopeClaim> ApiScopeClaims { get; set; }

        public DbSet<IdentityClaim> IdentityClaims { get; set; }

        public DbSet<ApiResourceClaim> ApiResourceClaims { get; set; }

        public DbSet<ClientGrantType> ClientGrantTypes { get; set; }

        public DbSet<ClientScope> ClientScopes { get; set; }

        public DbSet<ClientSecret> ClientSecrets { get; set; }

        public DbSet<ClientPostLogoutRedirectUri> ClientPostLogoutRedirectUris { get; set; }

        public DbSet<ClientCorsOrigin> ClientCorsOrigins { get; set; }

        public DbSet<ClientIdPRestriction> ClientIdPRestrictions { get; set; }

        public DbSet<ClientRedirectUri> ClientRedirectUris { get; set; }

        public DbSet<ClientClaim> ClientClaims { get; set; }

        public DbSet<ClientProperty> ClientProperties { get; set; }

        //public DbSet<IdentityResource> IdentityResources { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            ConfigureIdentityContext(builder);
        }

        private void ConfigureIdentityContext(ModelBuilder builder)
        {
            builder.Entity<IdentityResource>().ToTable("bnauth_identityresources");
            builder.Entity<IdentityClaim>().ToTable("bnauth_identityclaims");
            builder.Entity<ApiSecret>().ToTable("bnauth_apisecrets");
            builder.Entity<ApiResource>().ToTable("bnauth_apiresources");
            builder.Entity<ApiResourceClaim>().ToTable("bnauth_apiclaims");
            builder.Entity<ApiScope>().ToTable("bnauth_apiscopes");
            builder.Entity<ApiScopeClaim>().ToTable("bnauth_apiscopeclaims");
            builder.Entity<IdentityClaim>().ToTable("bnauth_identityclaims");

            builder.Entity<ClientGrantType>().ToTable("bnauth_clientgranttypes");
            builder.Entity<ClientScope>().ToTable("bnauth_clientscopes");

            builder.Entity<ClientSecret>().ToTable("bnauth_clientsecrets");
            builder.Entity<ClientPostLogoutRedirectUri>().ToTable("bnauth_clientpostlogoutredirecturis");
            builder.Entity<ClientCorsOrigin>().ToTable("bnauth_clientcorsorigins");
            builder.Entity<ClientIdPRestriction>().ToTable("bnauth_clientidprestrictions");

            builder.Entity<ClientRedirectUri>().ToTable("bnauth_clientredirecturis");
            builder.Entity<ClientClaim>().ToTable("bnauth_clientclaims");
            builder.Entity<ClientProperty>().ToTable("bnauth_clientproperties");

            builder.Entity<Client>().ToTable("bnauth_clients");

            builder.Entity<IdentityResourceProperty>().ToTable("bnauth_identityproperties");
            builder.Entity<ApiResourceProperty>().ToTable("bnauth_apiproperties");
        }
    }
}





