using Microsoft.AspNetCore.Identity;
using FDS.Models;
using FDS.Data.Models;

namespace FDS.Service.Models.Authentication.User
{
    public class CreateUserResponse
    {
        public ApplicationUser? User { get; set; }
    }
}
