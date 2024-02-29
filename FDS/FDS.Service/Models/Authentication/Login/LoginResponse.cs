using FDS.Models;
using FDS.Service.Models.Authentication.User;

namespace FDS.Service.Models.Authentication.Login
{
    public class LoginResponse
    {
        public UserDto? User { get; set; }
        public TokenType? Token { get; set; }
        public TokenType? RefreshToken { get; set; }
    }
}
