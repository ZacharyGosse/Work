using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Data.Entity.Validation;
using System.Drawing;
using System.Text;
using System.Web;

namespace SecureLogin.Models
{
    public class Log
    {
        [Required]
        [StringLength(15)]
        public string username { get; set; }
        [Required]
        public string action { get; set; }
        [Required]
        public string message { get; set; }
        [Key]
        public System.DateTime timestamp { get; set; }
       
    }


    public class LogDbContext : DbContext
    {
        public DbSet<Log> Logs { get; set; }

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