namespace SecureLogin.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class Users1 : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Users", "avatar", c => c.Binary());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Users", "avatar");
        }
    }
}
