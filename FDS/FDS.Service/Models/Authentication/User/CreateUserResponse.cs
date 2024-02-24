using Microsoft.AspNetCore.Identity;
using FDS.Models;
using FDS.Data.Models;

namespace FDS.Service.Models.Authentication.User
{
    public class CreateUserResponse
    {
        public string? Token { get; set; }
        public ApplicationUser? User { get; set; }
    }
}
