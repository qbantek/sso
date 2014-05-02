using System.Data.Entity.Migrations;

namespace SSO.Migrations
{
    public partial class FinAppsUserToken : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.AspNetUsers", "FinAppsUserToken", c => c.String());
        }

        public override void Down()
        {
            DropColumn("dbo.AspNetUsers", "FinAppsUserToken");
        }
    }
}