using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Data.Entity.Validation;
using System.Drawing;
using System.Text;

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

        public byte[] avatar {get;set;}
       
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