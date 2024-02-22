using FDS.Models;
using FDS.Models.Authentication.Login;
using FDS.Models.Authentication.SignUp;
using FDS.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FDS.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthenticationController(IAuthenticationService authenticationService,UserManager<IdentityUser> userManager)
        {
            _authenticationService = authenticationService;
            _userManager = userManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser,String role)
        {
            var result = await _authenticationService.RegisterUserAsync(registerUser, role);

            if (result.Success)
            {
                return StatusCode(StatusCodes.Status201Created, new Response {Success=result.Success, Status =  result.Status , Message = result.Message});
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Success = result.Success, Status = result.Status, Message = result.Message });
            }
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginResponse = await _authenticationService.LoginUserAsync(loginModel);
            if (loginResponse.User == null)
            {
                return BadRequest(new Response
                {
                    Success = false,
                    Status = "Error",
                    Message = "Username or password is incorrect",
                });
            }
            return Ok(new Response
            {
                Data = loginResponse,
                Success = true,
                Status = "Success",
                Message = "Login Successfull",
            });

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
