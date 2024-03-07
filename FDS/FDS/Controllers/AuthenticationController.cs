using FDS.Data.Models;
using FDS.Models;
using FDS.Service.Models.Authentication.Login;
using FDS.Service.Models.Authentication.SignUp;
using FDS.Service.Models.Authentication.User;
using FDS.Service.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Data;


namespace FDS.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserManagement _user;

        public AuthenticationController(UserManager<ApplicationUser> userManager, IUserManagement user)
        {
            _userManager = userManager;
            _user = user;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            if (registerUser == null)
            {
                return BadRequest();
            }
            var tokenResponse = await _user.CreateUserAsync(registerUser);

            if (tokenResponse.IsSuccess && tokenResponse.Response != null)
            {
                if (registerUser.Roles != null && tokenResponse.Response.User !=null)
                {
                    await _user.AsignRoleAsync(registerUser.Roles, tokenResponse.Response.User);
                }
                return Ok(tokenResponse);
                    
            }
            return BadRequest(tokenResponse);
                
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var jwt = await _user.LoginUserWithJWTokenAsync(loginModel);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return BadRequest(jwt); 
        }

        [HttpGet("{email}/roles")]
        public async Task<IActionResult> GetUserRoles(string email)
        {
            var roles = await _user.GetUserRolesAsync(email);
            if (roles.IsSuccess)
            {
                return Ok(roles);
            }
            return BadRequest(roles);
        }
        [HttpPost]
        [Route("setrole")]
        //[Authorize(Roles = "Admin")] 
        public async Task<IActionResult> SetRoles(string email, List<string> roles)
        {
            var role = await _user.SetRolesAsync(email, roles);
            if (role.IsSuccess)
            {
                return Ok(role);
            }
            return BadRequest(role);
        }

        [HttpPost("remove")]
        public async Task<IActionResult> RemoveRoles(string email, List<string> roles)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound($"User with email '{email}' not found.");
            }

            var result = await _userManager.RemoveFromRolesAsync(user, roles);
            if (result.Succeeded)
            {
                return Ok(new Response { Success = true, Message = "Roles removed successfully." });
            }
            else
            {
                return StatusCode(500, new Response { Success = false, Message = "Failed to remove roles." });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword( string email)
        {
            var result = await _user.ForgotPasswordAsync(email);
            if (result.IsSuccess)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }
        [HttpGet]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(string token , string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return await Task.FromResult(Ok(new
            {
                model
            }));
        }
        [HttpPost]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var result = await _user.ResetPasswordAsync(resetPassword);
            if (result.IsSuccess)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }

        
        [HttpPost]
        [Route("Refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel token)
        {
            var jwt = await _user.RenewAccessToken(token);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Error", Message = $"Invalid Code" });

        }
    }
}
