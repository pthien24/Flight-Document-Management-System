using FDS.Models.Authentication.SignUp;

namespace FDS.Services
{
    public interface IAuthenticationService
    {
        Task<AuthenticationResult> RegisterUserAsync(RegisterUser registerUser, string role);
    }

    public class AuthenticationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
    }
}
