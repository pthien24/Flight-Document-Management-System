using FDS.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Identity;

namespace FDS.Services
{
    public class AuthenticationService : IAuthenticationService 
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthenticationService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public Task<AuthenticationResult> RegisterUserAsync(RegisterUser registerUser, string role)
        {
            throw new NotImplementedException();
        }
    }
}
