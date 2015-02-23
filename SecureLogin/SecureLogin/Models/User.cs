using System.Drawing;
using System.Data.Entity;

namespace SecureLogin.Models
{
    public class User
    {
        public int Id { get; set; }
        public string username { get; set; }
        public string email { get; set; }
        public string password { get; set; }
        //public Image avatar { get; set; }

    }

    public class UserDBContext : DbContext
    {
        public DbSet<User> Users { get; set; }
    }
}