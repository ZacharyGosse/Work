namespace SecureLogin.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class Users : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "hashpwd", c => c.Binary());
            AddColumn("dbo.Users", "salt", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Users", "salt");
            DropColumn("dbo.Users", "hashpwd");
        }
    }
}
