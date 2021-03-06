﻿using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Data.Entity.Validation;
using System.Drawing;
using System.Text;
using System.Web;

namespace SecureLogin.Models
{
    public class User
    {
        [Key]
        [Required]
        [StringLength(15)]
        public string username { get; set; }
        [EmailAddress]
        public string email { get; set; }
        [Required]

        [DataType(DataType.Password)]
        [StringLength(150,MinimumLength=7)]

        public string password { get; set; }
        public string salt { get; set; }

        public string actString { get; set; }

        public string forString { get; set; }

        public string unlString { get; set; }
       
        public string avPath {get;set;}

        public string thumbPath { get; set; }
       
        public int attempts  { get; set; }

        public bool activated { get; set; }

        public bool locked { get; set; }
    }
    
    public class RegisterUser{
         [Key]
        [Required]
        [StringLength(15)]
        public string username { get; set; }
        [EmailAddress]
        public string email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [StringLength(150, MinimumLength = 7)]
        [RegularExpression(@"(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{7,15}", ErrorMessage = "Password must contain 7-15 characters, at least one number, and both lower and upper case letters.")]
        public string newpass { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [StringLength(150, MinimumLength = 7)]
        [Compare("newpass", ErrorMessage = "Passwords Do Not Match")]
        public string confpass { get; set; }
    }


    public class UserPassChange
    {
        [Key]
        [Required]
        [StringLength(15)]
        public string username { get; set; }
        [EmailAddress]
        public string email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [StringLength(150, MinimumLength = 7)]

        public string password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [StringLength(150, MinimumLength = 7)]
        [RegularExpression(@"(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{7,15}", ErrorMessage = "Password must contain 7-15 characters, at least one number, and both lower and upper case letters.")]
        public string newpass { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [StringLength(150, MinimumLength = 7)]
        [Compare("newpass", ErrorMessage = "Passwords Do Not Match")]
        public string confpass { get; set; }
        public string salt { get; set; }

        public string avPath { get; set; }

        public string thumbPath { get; set; }

        [DataType(DataType.Upload)]
        public HttpPostedFileBase Image { get; set; }
         

    }



    public class UserDBContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public override int SaveChanges()
        {
            try
            {
                return base.SaveChanges();
            }
            catch (DbEntityValidationException ex)
            {
                StringBuilder sb = new StringBuilder();

                foreach (var failure in ex.EntityValidationErrors)
                {
                    sb.AppendFormat("{0} failed validation\n", failure.Entry.Entity.GetType());
                    foreach (var error in failure.ValidationErrors)
                    {
                        sb.AppendFormat("- {0} : {1}", error.PropertyName, error.ErrorMessage);
                        sb.AppendLine();
                    }
                }

                throw new DbEntityValidationException(
                    "Entity Validation Failed - errors follow:\n" +
                    sb.ToString(), ex
                ); // Add the original exception as the innerException
            }
        }
    }
}