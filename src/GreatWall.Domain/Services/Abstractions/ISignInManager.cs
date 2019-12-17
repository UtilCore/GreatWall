using System.Threading.Tasks;
using GreatWall.Domain.Models;
using GreatWall.Results;
using Util.Domains.Services;

namespace GreatWall.Domain.Services.Abstractions {
    /// <summary>
    /// 登录服务
    /// </summary>
    public interface ISignInManager : IDomainService {
        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="password">密码</param>
        /// <param name="isPersistent">cookie是否持久保留,设置为false,当关闭浏览器则cookie失效</param>
        /// <param name="lockoutOnFailure">达到登录失败次数是否锁定</param>
        Task<SignInResult> SignInAsync( User user, string password, bool isPersistent = false, bool lockoutOnFailure = true );
        /// <summary>
        /// 生成登录令牌
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="application">应用程序</param>
        Task<string> GenerateSignInTokenAsync( string phone, string application = "" );
        /// <summary>
        /// 令牌登录
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="token">令牌</param>
        /// <param name="isPersistent">cookie是否持久保留,设置为false,当关闭浏览器则cookie失效</param>
        /// <param name="lockoutOnFailure">达到登录失败次数是否锁定</param>
        /// <param name="application">应用程序</param>
        Task<SignInResult> TokenSignInAsync( string phone, string token, bool isPersistent,bool lockoutOnFailure, string application = "" );
        /// <summary>
        /// 退出登录
        /// </summary>
        Task SignOutAsync();
    }
}