using FDS.Service.Models;
using FDS.Service.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Identity;
using FDS.Service.Models.Authentication.User;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FDS.Data.Models;
using FDS.Service.Models.Authentication.Login;
using FDS.Models;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc.Abstractions;

namespace FDS.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public UserManagement(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;

        }
        public async Task<ApplicationUser> FindUserByEmailAsync(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }
        public async Task<ApiResponse<RoleResponse>> GetUserRolesAsync(string email)
        {
            var user = await FindUserByEmailAsync(email);
            if (user == null)
            {
                return new ApiResponse<RoleResponse> { IsSuccess = false, StatusCode = 404, Message = $"User with email '{email}' not found." };
            }
            var userRole = await _userManager.GetRolesAsync(user);
            var response = new RoleResponse
            {
                mail = email,
                role = userRole.ToList()
            };

            return new ApiResponse<RoleResponse> { IsSuccess = true, StatusCode = 200, Message = "User roles retrieved successfully.", Response = response };
        }
        public async Task<ApiResponse<string>> SetRolesAsync(string email, List<string> roles)
        {
            var user = await FindUserByEmailAsync(email);
            if (user == null)
            {
                return new ApiResponse<string> { IsSuccess = false, StatusCode = 404, Message = $"User with email '{email}' not found." };
            }

            var result = await AsignRoleAsync(roles,user);
            if (result.IsSuccess)
            {
                return new ApiResponse<string> { IsSuccess = true, StatusCode = 200, Message = "Roles assigned successfully."  };
            }
            else
            {
                return new ApiResponse<string> { IsSuccess = false, StatusCode = 500, Message = "Failed to assign roles." };
            }
        }
        public async Task<ApiResponse<List<string>>> AsignRoleAsync(List<string> role, ApplicationUser user)
        {
            var asignedRole = new List<string>();
            foreach (var roleItem in role) {
                if (await _roleManager.RoleExistsAsync(roleItem))
                {

                    if (!await _userManager.IsInRoleAsync(user,roleItem))
                    {
                        await _userManager.AddToRoleAsync(user, roleItem);
                        asignedRole.Add(roleItem);
                    }
                }
            }
            return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200, Message = "Role has been assigned ",Response = asignedRole };

        }
        public Task<ApiResponse<string>> RemoveRolesAsync(string email, List<string> roles)
        {
            throw new NotImplementedException();
        }
        public async Task<ApiResponse<CreateUserResponse>> CreateUserAsync(RegisterUser registerUser)
        {
            if (string.IsNullOrEmpty(registerUser.Email) || string.IsNullOrEmpty(registerUser.UserName) || string.IsNullOrEmpty(registerUser.Password))
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 400, Message = "Please provide all required fields" };
            }
            //Check User Exist 
            var userExist = FindUserByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse> {IsSuccess = false, StatusCode= 403, Message = "User already exists!" };
            }
            var passwordValidator = new PasswordValidator<ApplicationUser>();
            var validationResult = await passwordValidator.ValidateAsync(_userManager, null, registerUser.Password);
            if (!validationResult.Succeeded)
            {
                var errorMessage = string.Join(", ", validationResult.Errors.Select(e => e.Description));

                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = errorMessage
                };
            }
            if (!IsEmailAllowed(registerUser.Email))
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 400, Message = "Only emails from vietjet.com domain are allowed!" };
            }
            ApplicationUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
            };
            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {
                return new ApiResponse<CreateUserResponse> {Response = new CreateUserResponse()
                {
                    User = user,
                }, IsSuccess = true, StatusCode = 201, Message = "User Created" };
            }
            else
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 500, Message = "User Failed to Create" };
            }
        }
        public async Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(LoginModel loginModel)
        {
            var user = await FindUserByEmailAsync(loginModel.Email);

            if (string.IsNullOrEmpty(loginModel.Email) || string.IsNullOrEmpty(loginModel.Password))
            {
                return new ApiResponse<LoginResponse> { IsSuccess = false, StatusCode = 400, Message = "Please provide email and password" };
            }

            if (!IsEmailAllowed(loginModel.Email))
            {
                return new ApiResponse<LoginResponse> { IsSuccess = false, StatusCode = 400, Message = "Only emails from vietjet.com domain are allowed!" };
            }
            var passwordValid = await _userManager.CheckPasswordAsync(user, loginModel.Password);
            if (!passwordValid)
            {
                return new ApiResponse<LoginResponse>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = "Invalid email or password"
                };
            }
            if (user != null)
            {
                return await GetJwtTokenAsync(user);


            }
            return new ApiResponse<LoginResponse>()
            {
                Response = new LoginResponse()
                {

                },
                IsSuccess = false,
                StatusCode = 400,
                Message = $"login failed"
            };
        }

        public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }
            var jwtToken = GetToken(authClaims);  //token
            var refreshtoken = GenerateRefreshToken();

            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int RefreshToken);

            user.RefreshToken = refreshtoken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(RefreshToken);



            await _userManager.UpdateAsync(user);
            var userDto = new UserDto
            {
                ID = user.Id,
                Email = user.Email,
                Name = user.UserName
            };
            return new ApiResponse<LoginResponse>
            {
                Response = new LoginResponse()
                {
                    User = userDto,
                    Token = new TokenType()
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        ExpiryTokenDate = jwtToken.ValidTo
                    },
                    RefreshToken = new TokenType()
                    {
                        Token = user.RefreshToken,
                        ExpiryTokenDate = (DateTime)user.RefreshTokenExpiry
                    }
                    
                },
                IsSuccess = true,
                StatusCode = 200,
                Message = $"Token created adn user login successfully"
            };
        }

        public async Task<ApiResponse<ResetPasswordResponse>> ForgotPasswordAsync(string email)
        {
            var user = await FindUserByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                var resetPasswordLink = $"{_configuration["AutheUrl"]}/reset-password?token={token}&email={Uri.EscapeDataString(email)}";
                return new ApiResponse<ResetPasswordResponse>
                {
                    Response = new ResetPasswordResponse()
                    {
                        ResetPasswordLink = resetPasswordLink
                    },
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"link reset created"
                };
            }
            return new ApiResponse<ResetPasswordResponse>
            {
                Response = new ResetPasswordResponse()
                {
                },
                IsSuccess = false,
                StatusCode = 400,
                Message = "Could not send reset password link"
            };
        }

        public async Task<ApiResponse<string>> ResetPasswordAsync(ResetPassword resetPassword)
        {
            var user = await FindUserByEmailAsync(resetPassword.Email);

            var passwordCheck = await _userManager.CheckPasswordAsync(user, resetPassword.Password);
            if (passwordCheck)
            {
                return new ApiResponse<string> { IsSuccess = false, StatusCode = 400, Message = "New password must be different from the old password" };
            }

            if (user != null)
            {
                var resetPassRes = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (resetPassRes.Succeeded)
                {
                    return new ApiResponse<string> { IsSuccess =true,StatusCode = 200, Message = "Password has been changed" };
                }

                return new ApiResponse<string> { IsSuccess = false, StatusCode = 400, Message = "Password reset failed" };
            }

            return new ApiResponse<string> { IsSuccess = false, StatusCode = 400, Message = "User not found" };
        }
        public async Task<ApiResponse<LoginResponse>> RenewAccessToken(RefreshTokenModel tokens)
        {

            var AccessToken = tokens.AccessToken;
            var RefreshToken = tokens.RefreshToken;

            var pricipal = GetClaimsPrincipal(AccessToken.Token);
            var user = await _userManager.FindByNameAsync(pricipal.Identity.Name);
            if (user.RefreshToken != RefreshToken.Token && RefreshToken.ExpiryTokenDate >= DateTime.UtcNow)
            {
                 return new ApiResponse<LoginResponse> { IsSuccess = false, StatusCode = 400, Message = "token invalid or expiried" };
            }
            var response = await GetJwtTokenAsync(user);
            return response;
        } 

        private ClaimsPrincipal GetClaimsPrincipal(string accesstoken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accesstoken, tokenValidationParameters, out SecurityToken securityToken);

            return principal;
        }
        private bool IsEmailAllowed(string email)
        {
            string[] emailParts = email.Split('@');
            if (emailParts.Length == 2)
            {
                return emailParts[1].Equals("vietjetair.com", StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
           
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int TokenValidityInMinutes);
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddMinutes(TokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            var range = System.Security.Cryptography.RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        
    }
}
