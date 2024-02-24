using System.ComponentModel.DataAnnotations;

namespace FDS.Service.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage ="user name is re")]
        public string? UserName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "email is re")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "password is re")]
        public string? Password { get; set; }
        public List<string>? Roles { get; set; }
    }
}
