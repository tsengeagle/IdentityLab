using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CustomIdentity.Startup))]
namespace CustomIdentity
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
