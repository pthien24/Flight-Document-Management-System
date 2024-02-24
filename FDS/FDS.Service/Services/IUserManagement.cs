using FDS.Data.Models;
using FDS.Service.Models;
using FDS.Service.Models.Authentication.Login;
using FDS.Service.Models.Authentication.SignUp;
using FDS.Service.Models.Authentication.User;
using Microsoft.AspNetCore.Identity;

namespace FDS.Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<CreateUserResponse>> CreateUserAsync(RegisterUser registerUser);
        Task<ApiResponse<List<string>>> AsignRoleAsync(List<string> role, ApplicationUser user);
        Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user);
        Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(LoginModel loginmodel);
    }
}
