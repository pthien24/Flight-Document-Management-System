using System.ComponentModel.DataAnnotations;

namespace FDS.Service.Models.Authentication.SignUp
{
    public class ResetPassword
    {
        public string Password { get; set; } = null!;
        [Compare("Password", ErrorMessage = "The password and comfirm password do not match")]
        public string ConfirmPassword { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string Token { get; set; } = null!;
    }
}
