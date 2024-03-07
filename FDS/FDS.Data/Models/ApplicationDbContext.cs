using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FDS.Data.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }
        private static void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                    new IdentityRole() {
                        Name = "Admin" ,
                        ConcurrencyStamp = "1" , 
                        NormalizedName = "Admin"
                    },
                    new IdentityRole()
                    {
                        Name = "Pilot",
                        ConcurrencyStamp = "2",
                        NormalizedName = "Pilot"
                    },
                    new IdentityRole()
                    {
                        Name = "Emloyee",
                        ConcurrencyStamp = "3",
                        NormalizedName = "Emloyee"
                    },
                    new IdentityRole()
                    {
                        Name = "Attendant",
                        ConcurrencyStamp = "4",
                        NormalizedName = "Attendant"
                    }
                    
                 );
        }
    }
}
