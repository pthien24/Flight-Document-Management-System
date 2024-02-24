using FDS.Data.Models;
using FDS.Models;
using FDS.Service.Models.Authentication.Login;
using FDS.Service.Models.Authentication.SignUp;
using FDS.Service.Services;
using FDS.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;


namespace FDS.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserManagement _user;

        public AuthenticationController(IAuthenticationService authenticationService,UserManager<ApplicationUser> userManager, IUserManagement user
            )
        {
            _authenticationService = authenticationService;
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
                return StatusCode(StatusCodes.Status200OK,
                        new Response { Success = true, Message = $"{tokenResponse.Message}" });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                  new Response { Message = tokenResponse?.Message , Success = false });
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
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });

        }

        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword( string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var link = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                return StatusCode(StatusCodes.Status200OK,
                    new Response {Success = true, Status = "Success" , Message = $"{link}"});
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Success = false, Status = "Error", Message = "Could not sent link reset password" });
        }
        [HttpGet]
        [Route("Reset-Password")]
        public async Task<IActionResult> ResetPassword(string token , string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new
            {
                model
            }) ;
        }
}
}
