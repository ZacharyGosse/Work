using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SecureLogin.Startup))]
namespace SecureLogin
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
