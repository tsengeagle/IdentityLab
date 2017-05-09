using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using CustomIdentity.Models;
using Microsoft.Owin.Security;

namespace CustomIdentity
{
    public partial class Startup
    {
        // 如需設定驗證的詳細資訊，請瀏覽 http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // 設定資料庫內容、使用者管理員和登入管理員，以針對每個要求使用單一執行個體
            app.CreatePerOwinContext(CustomUserManager.Create);
            app.CreatePerOwinContext<CustomSignInManager>(CustomSignInManager.Create);

            // 讓應用程式使用 Cookie 儲存已登入使用者的資訊
            // 並使用 Cookie 暫時儲存使用者利用協力廠商登入提供者登入的相關資訊；
            // 在 Cookie 中設定簽章
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // 讓應用程式在使用者登入時驗證安全性戳記。
                    // 這是您變更密碼或將外部登入新增至帳戶時所使用的安全性功能。  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<CustomUserManager, CustomUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => manager.GenerateUserIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie))
                }
            });

        }
    }

    public class CustomSignInManager : SignInManager<CustomUser, string>
    {
        public CustomSignInManager(UserManager<CustomUser, string> userManager, IAuthenticationManager authenticationManager) : base(userManager, authenticationManager)
        { }

        public static CustomSignInManager Create(IdentityFactoryOptions<CustomSignInManager> identityFactoryOptions, IOwinContext context)
        {
            return new CustomSignInManager(context.GetUserManager<CustomUserManager>(), context.Authentication);
        }

        public override async Task<SignInStatus> PasswordSignInAsync(string userName, string password, bool isPersistent, bool shouldLockout)
        {
            var user = new CustomUser() { Id = "1", UserName = "test" };

            var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties(), identity);

            return SignInStatus.Success;
        }
    }

    public class CustomUserManager : UserManager<CustomUser>
    {
        public CustomUserManager(IUserStore<CustomUser> store) : base(store)
        { }

        public static CustomUserManager Create()
        {
            var manager = new CustomUserManager(new CustomUserStore());
            return manager;
        }

        public Task<ClaimsIdentity> GenerateUserIdentityAsync(CustomUser user, string applicationCookie)
        {
            var baseTask = base.CreateIdentityAsync(user, applicationCookie);
            var task = Task.Run(
                () =>
                {
                    var identity = baseTask.Result;
                    return identity;
                });
            return task;
        }
    }

    public class CustomUserStore : IUserStore<CustomUser>
    {
        public Task CreateAsync(CustomUser user)
        {
            return Task.Delay(1);
        }

        public Task UpdateAsync(CustomUser user)
        {
            return Task.Delay(1);
        }

        public Task DeleteAsync(CustomUser user)
        {
            return Task.Delay(1);
        }

        public Task<CustomUser> FindByIdAsync(string userId)
        {
            return new Task<CustomUser>(() => new CustomUser() { Id = userId, UserName = "Test" + userId });
        }

        public Task<CustomUser> FindByNameAsync(string userName)
        {
            return new Task<CustomUser>(() => new CustomUser() { Id = "Id" + userName, UserName = userName });
        }

        public void Dispose()
        {
        }
    }

    public class CustomUser : IUser<string>
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}