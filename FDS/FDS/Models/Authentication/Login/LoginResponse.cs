namespace FDS.Models.Authentication.Login
{
    public class LoginResponse
    {
        public UserDto? User { get; set; }
        public string? Token { get; set; }
    }
}
