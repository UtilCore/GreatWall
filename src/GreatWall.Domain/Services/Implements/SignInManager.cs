using System.Threading.Tasks;
using GreatWall.Domain.Models;
using GreatWall.Domain.Services.Abstractions;
using GreatWall.Purposes;
using GreatWall.Results;
using Util;

namespace GreatWall.Domain.Services.Implements {
    /// <summary>
    /// 登录服务
    /// </summary>
    public class SignInManager : ISignInManager {
        /// <summary>
        /// 初始化登录服务
        /// </summary>
        /// <param name="signInManager">Identity登录服务</param>
        /// <param name="userManager">用户服务</param>
        public SignInManager( IdentitySignInManager signInManager, IUserManager userManager ) {
            IdentitySignInManager = signInManager;
            UserManager = userManager;
        }

        /// <summary>
        /// Identity登录服务
        /// </summary>
        protected IdentitySignInManager IdentitySignInManager { get; }
        /// <summary>
        /// 用户服务
        /// </summary>
        protected IUserManager UserManager { get; }

        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="password">密码</param>
        /// <param name="isPersistent">cookie是否持久保留,设置为false,当关闭浏览器则cookie失效</param>
        /// <param name="lockoutOnFailure">达到登录失败次数是否锁定</param>
        public async Task<SignInResult> SignInAsync( User user, string password, bool isPersistent, bool lockoutOnFailure ) {
            if( user == null )
                return new SignInResult( SignInState.Failed, null, GreatWallResource.InvalidAccountOrPassword );
            var signInResult = await IdentitySignInManager.PasswordSignInAsync( user, password, isPersistent, lockoutOnFailure );
            return GetSignInResult( user, signInResult );
        }

        /// <summary>
        /// 获取登录结果
        /// </summary>
        private SignInResult GetSignInResult( User user, Microsoft.AspNetCore.Identity.SignInResult signInResult ) {
            if( signInResult.IsNotAllowed )
                return new SignInResult( SignInState.Failed, null, GreatWallResource.UserIsDisabled );
            if( signInResult.IsLockedOut )
                return new SignInResult( SignInState.Failed, null, GreatWallResource.LoginFailLock );
            if( signInResult.Succeeded )
                return new SignInResult( SignInState.Succeeded, user.Id.SafeString() );
            if( signInResult.RequiresTwoFactor )
                return new SignInResult( SignInState.TwoFactor, user.Id.SafeString() );
            return new SignInResult( SignInState.Failed, null, GreatWallResource.InvalidAccountOrPassword );
        }

        /// <summary>
        /// 生成登录令牌
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="application">应用程序</param>
        public async Task<string> GenerateSignInTokenAsync( string phone, string application = "" ) {
            return await UserManager.GenerateTokenAsync( phone, TokenPurpose.SignIn, application );
        }

        /// <summary>
        /// 令牌登录
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="token">令牌</param>
        /// <param name="isPersistent">cookie是否持久保留,设置为false,当关闭浏览器则cookie失效</param>
        /// <param name="lockoutOnFailure">达到登录失败次数是否锁定</param>
        /// <param name="application">应用程序</param>
        public async Task<SignInResult> TokenSignInAsync( string phone, string token,bool isPersistent, bool lockoutOnFailure, string application = "" ) {
            var user = await UserManager.FindByPhoneAsync( phone );
            if( user == null )
                return new SignInResult( SignInState.Failed, null, GreatWallResource.InvalidAccountOrPassword );
            var success = await UserManager.VerifyTokenAsync( user, TokenPurpose.SignIn, token, application );
            var signInResult = await IdentitySignInManager.TokenSignInAsync( user, success, isPersistent, lockoutOnFailure );
            return GetSignInResult( user, signInResult );
        }

        /// <summary>
        /// 退出登录
        /// </summary>
        public async Task SignOutAsync() {
            await IdentitySignInManager.SignOutAsync();
        }
    }
}
