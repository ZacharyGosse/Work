﻿using System.Data.Entity;
using System.Drawing;

namespace SecureLogin.Models
{
    public class User
    {
        public int Id { get; set; }
        public string username { get; set; }
        public string email { get; set; }
        public string password { get; set; }
        public byte[] hashpwd { get; set; }
        public string salt { get; set; }

        public byte[] avatar {get;set;}
       
    }

    public class UserDBContext : DbContext
    {
        public DbSet<User> Users { get; set; }
    }
}