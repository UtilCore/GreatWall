using System;
using System.Threading.Tasks;
using GreatWall.Domain.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace GreatWall.Domain.Services.Implements {
    /// <summary>
    /// Identity登录服务
    /// </summary>
    public class IdentitySignInManager : SignInManager<User> {
        /// <summary>
        /// 初始化Identity登录服务
        /// </summary>
        /// <param name="userManager">Identity用户服务</param>
        /// <param name="contextAccessor">HttpContext访问器</param>
        /// <param name="claimsFactory">用户声明工厂</param>
        /// <param name="optionsAccessor">Identity配置</param>
        /// <param name="logger">日志</param>
        /// <param name="schemes">认证架构提供程序</param>
        public IdentitySignInManager( UserManager<User> userManager, IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<User> claimsFactory, IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<User>> logger, IAuthenticationSchemeProvider schemes )
                : base( userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes ) {
        }

        /// <summary>
        /// 是否允许登录
        /// </summary>
        /// <param name="user">用户</param>
        public override async Task<bool> CanSignInAsync( User user ) {
            if( user.Enabled == false )
                return false;
            return await base.CanSignInAsync( user );
        }

        /// <summary>
        /// 令牌登录
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="verifySuccess">令牌是否验证成功</param>
        /// <param name="isPersistent">cookie是否持久保留,设置为false,当关闭浏览器则cookie失效</param>
        /// <param name="lockoutOnFailure">达到登录失败次数是否锁定</param>
        public async Task<SignInResult> TokenSignInAsync( User user, bool verifySuccess, bool isPersistent, bool lockoutOnFailure ) {
            var attempt = await TokenSignInAsync( user, verifySuccess, lockoutOnFailure );
            return attempt.Succeeded
                ? await SignInOrTwoFactorAsync( user, isPersistent )
                : attempt;
        }

        /// <summary>
        /// 令牌登录
        /// </summary>
        private async Task<SignInResult> TokenSignInAsync( User user, bool verifySuccess, bool lockoutOnFailure ) {
            if( user == null ) {
                throw new ArgumentNullException( nameof( user ) );
            }
            var error = await PreSignInCheck( user );
            if( error != null ) {
                return error;
            }
            if( verifySuccess ) {
                var alwaysLockout = AppContext.TryGetSwitch( "Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", out var enabled ) && enabled;
                if( alwaysLockout || !await IsTfaEnabled( user ) ) {
                    await ResetLockout( user );
                }
                return SignInResult.Success;
            }
            Logger.LogWarning( 2, "User {userId} failed to provide the correct password.", await UserManager.GetUserIdAsync( user ) );
            if( UserManager.SupportsUserLockout && lockoutOnFailure ) {
                await UserManager.AccessFailedAsync( user );
                if( await UserManager.IsLockedOutAsync( user ) ) {
                    return await LockedOut( user );
                }
            }
            return SignInResult.Failed;
        }

        /// <summary>
        /// 用户是否启用
        /// </summary>
        private async Task<bool> IsTfaEnabled( User user )
            => UserManager.SupportsUserTwoFactor &&
               await UserManager.GetTwoFactorEnabledAsync( user ) &&
               ( await UserManager.GetValidTwoFactorProvidersAsync( user ) ).Count > 0;
    }
}
