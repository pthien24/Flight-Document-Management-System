using FDS.Models;
using FDS.Models.Authentication.Login;
using FDS.Models.Authentication.SignUp;

namespace FDS.Services
{
    public interface IAuthenticationService
    {
        Task<LoginResponse> LoginUserAsync(LoginModel loginModel);
        Task<Response> RegisterUserAsync(RegisterUser registerUser, string role);
    }
}
