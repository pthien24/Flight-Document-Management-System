using FDS.Models;
using FDS.Service.Models.Authentication.Login;
using FDS.Service.Models.Authentication.SignUp;
using FDS.Service.Models.Authentication.User;

namespace FDS.Services
{
    public interface IAuthenticationService
    {
        Task<Response> RegisterUserAsync(RegisterUser registerUser, string role);
    }
}
