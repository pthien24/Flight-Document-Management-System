using FDS.Models;
using FDS.Models.Authentication.Login;
using FDS.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FDS.Services
{
    public class AuthenticationService : IAuthenticationService 
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthenticationService(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        public async Task<LoginResponse> LoginUserAsync(LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);
            if (user != null)
            {
                var result = await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, false);

                if (result.Succeeded)
                {
                    // User successfully signed in
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }
                    var jwtToken = GetToken(authClaims);

                    var userDto = new UserDto
                    {
                        ID = user.Id,
                        Email = user.Email,
                        Name = user.UserName
                    };
                    // Generate JWT token or any other authentication token here
                    var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
                    return new LoginResponse { User = userDto, Token = token };
                }
            }
            // Authentication failed
            return new LoginResponse { User = null, Token = null };
        }

        public async Task<Response> RegisterUserAsync(RegisterUser registerUser, string role)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new Response { Success = false, Status = "Error", Message = "email user already exists!" };
            }

            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
            };
            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return new Response { Success = false, Status = "Error", Message = "User Failed to Create" };
                }
                await _userManager.AddToRoleAsync(user, role);
                return new Response { Success = true, Status = "Success", Message = "User created SuccessFully" };

            }
            else
            {
                return new Response { Success = false, Status = "Error", Message = "This Role Doesnot Exist." };
            }
        }
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(2),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
    }
}
