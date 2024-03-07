using FDS.Data.Models;
using FDS.Service.Models;
using FDS.Service.Models.Authentication.Login;
using FDS.Service.Models.Authentication.SignUp;
using FDS.Service.Models.Authentication.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FDS.Service.Services
{
    public interface IUserManagement
    {

        Task<ApplicationUser> FindUserByEmailAsync(string email);
        Task<ApiResponse<string>> SetRolesAsync(string email, List<string> roles);
        Task<ApiResponse<RoleResponse>> GetUserRolesAsync(string email);
        Task<ApiResponse<string>> RemoveRolesAsync(string email, List<string> roles);
        Task<ApiResponse<CreateUserResponse>> CreateUserAsync(RegisterUser registerUser);
        Task<ApiResponse<List<string>>> AsignRoleAsync(List<string> role, ApplicationUser user);
        Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user);
        Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(LoginModel loginmodel);
        Task<ApiResponse<ResetPasswordResponse>> ForgotPasswordAsync(string email);
        Task<ApiResponse<string>> ResetPasswordAsync(ResetPassword resetPassword);
        Task<ApiResponse<LoginResponse>> RenewAccessToken(RefreshTokenModel tokens);
    }
}
