using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SSO.Startup))]
namespace SSO
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
