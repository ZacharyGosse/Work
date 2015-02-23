using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Drawing;
using System.Data.Entity;

namespace SecureLogin.Models
{
    public class User
    {
        public string username { get; set; }
        public string email { get; set; }
        public string password { get; set; }
        public Image avatar { get; set; }

    }

    public class UserDBContext : DbContext
    {
        public DbSet<User> Users { get; set; }
    }
}