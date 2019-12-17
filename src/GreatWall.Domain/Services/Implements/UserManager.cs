using System;
using System.Threading.Tasks;
using GreatWall.Domain.Models;
using GreatWall.Domain.Repositories;
using GreatWall.Domain.Services.Abstractions;
using GreatWall.Extensions;
using GreatWall.Options;
using GreatWall.Purposes;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Util;
using Util.Domains.Services;

namespace GreatWall.Domain.Services.Implements {
    /// <summary>
    /// 用户服务
    /// </summary>
    public class UserManager : DomainServiceBase, IUserManager {

        #region 构造方法

        /// <summary>
        /// 初始化用户服务
        /// </summary>
        /// <param name="userManager">Identity用户服务</param>
        /// <param name="options">权限配置</param>
        /// <param name="userRepository">用户仓储</param>
        public UserManager( IdentityUserManager userManager, IOptions<PermissionOptions> options, IUserRepository userRepository ) {
            Manager = userManager;
            Options = options;
            UserRepository = userRepository;
        }

        #endregion

        #region 属性

        /// <summary>
        /// Identity用户服务
        /// </summary>
        private IdentityUserManager Manager { get; }
        /// <summary>
        /// 权限配置
        /// </summary>
        private IOptions<PermissionOptions> Options { get; }
        /// <summary>
        /// 用户仓储
        /// </summary>
        private IUserRepository UserRepository { get; }

        #endregion

        #region 创建用户

        /// <summary>
        /// 创建用户
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="password">密码</param>
        public async Task CreateAsync( User user, string password ) {
            if( user == null )
                throw new ArgumentNullException( nameof( user ) );
            user.Init();
            user.Validate();
            var result = await Manager.CreateAsync( user, password );
            result.ThrowIfError();
            user.SetPassword( password, Options?.Value.Store.StoreOriginalPassword );
        }

        #endregion

        #region 生成令牌

        /// <summary>
        /// 生成令牌
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="purpose">用途</param>
        /// <param name="application">应用程序</param>
        /// <param name="provider">令牌提供器</param>
        public async Task<string> GenerateTokenAsync( string phone, string purpose, string application = "", string provider = "" ) {
            var user = await GetUserOrDefault( phone );
            return await GenerateTokenAsync( user, purpose, application, provider );
        }

        /// <summary>
        /// 获取用户
        /// </summary>
        private async Task<User> GetUserOrDefault( string phone ) {
            var user = await this.FindByPhoneAsync( phone );
            if( user == null ) {
                user = new User() {
                    PhoneNumber = phone,
                    SecurityStamp = CreateSecurityStamp()
                };
            }
            return user;
        }

        /// <summary>
        /// 创建安全戳
        /// </summary>
        protected virtual string CreateSecurityStamp() {
            return "56df9984-bc05-460a-a4ce-9dec3922a5e9";
        }

        /// <summary>
        /// 生成令牌
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="purpose">用途</param>
        /// <param name="application">应用程序</param>
        /// <param name="provider">令牌提供器</param>
        public async Task<string> GenerateTokenAsync( User user, string purpose, string application = "", string provider = "" ) {
            user.CheckNull( nameof( user ) );
            purpose = GetPurpose( purpose, application );
            if( provider.IsEmpty() )
                provider = TokenOptions.DefaultPhoneProvider;
            return await Manager.GenerateUserTokenAsync( user, provider, purpose );
        }

        /// <summary>
        /// 获取用途
        /// </summary>
        private string GetPurpose( string purpose, string application ) {
            return $"{purpose}_{application}";
        }

        #endregion

        #region 验证令牌

        /// <summary>
        /// 验证令牌
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="purpose">用途</param>
        /// <param name="token">令牌</param>
        /// <param name="application">应用程序</param>
        /// <param name="provider">令牌提供器</param>
        public async Task<bool> VerifyTokenAsync( string phone, string purpose, string token, string application = "", string provider = "" ) {
            var user = await GetUserOrDefault( phone );
            return await VerifyTokenAsync( user, purpose, token, application, provider );
        }

        /// <summary>
        /// 验证令牌
        /// </summary>
        /// <param name="user">手机号</param>
        /// <param name="purpose">用途</param>
        /// <param name="token">令牌</param>
        /// <param name="application">应用程序</param>
        /// <param name="provider">令牌提供器</param>
        public async Task<bool> VerifyTokenAsync( User user, string purpose, string token, string application = "", string provider = "" ) {
            user.CheckNull( nameof( user ) );
            purpose = GetPurpose( purpose, application );
            if( provider.IsEmpty() )
                provider = TokenOptions.DefaultPhoneProvider;
            return await Manager.VerifyUserTokenAsync( user, provider, purpose, token );
        }

        #endregion

        #region 生成和验证手机号注册令牌

        /// <summary>
        /// 生成手机号注册令牌
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="application">应用程序</param>
        public async Task<string> GenerateRegisterTokenAsync( string phone, string application = "" ) {
            return await GenerateTokenAsync( phone, TokenPurpose.PhoneRegister, application );
        }

        /// <summary>
        /// 验证手机号注册令牌
        /// </summary>
        /// <param name="phone">手机号</param>
        /// <param name="token">令牌</param>
        /// <param name="application">应用程序</param>
        public async Task<bool> VerifyRegisterTokenAsync( string phone, string token, string application = "" ) {
            return await VerifyTokenAsync( phone, TokenPurpose.PhoneRegister, token, application );
        }

        #endregion

        #region 激活电子邮件

        /// <summary>
        /// 生成电子邮件确认令牌
        /// </summary>
        /// <param name="user">用户</param>
        public async Task<string> GenerateEmailConfirmationTokenAsync( User user ) {
            return await Manager.GenerateEmailConfirmationTokenAsync( user );
        }

        /// <summary>
        /// 激活电子邮件
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="token">令牌</param>
        public async Task ConfirmEmailAsync( User user, string token ) {
            var result = await Manager.ConfirmEmailAsync( user, token );
            result.ThrowIfError();
        }

        #endregion

        #region 电子邮件找回密码

        /// <summary>
        /// 生成电子邮件重置密码令牌
        /// </summary>
        /// <param name="user">用户</param>
        public async Task<string> GenerateEmailPasswordResetTokenAsync( User user ) {
            return await Manager.GenerateUserTokenAsync( user, TokenOptions.DefaultProvider, UserManager<User>.ResetPasswordTokenPurpose );
        }

        /// <summary>
        /// 通过电子邮件重置密码
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="token">令牌</param>
        /// <param name="newPassword">新密码</param>
        public async Task ResetPasswordByEmailAsync( User user, string token, string newPassword ) {
            var result = await Manager.ResetPasswordAsync( user, TokenOptions.DefaultProvider, token, newPassword );
            result.ThrowIfError();
        }

        #endregion

        #region 手机号找回密码

        /// <summary>
        /// 生成手机号重置密码令牌
        /// </summary>
        /// <param name="user">用户</param>
        public async Task<string> GeneratePhonePasswordResetTokenAsync( User user ) {
            return await Manager.GenerateUserTokenAsync( user, TokenOptions.DefaultPhoneProvider, UserManager<User>.ResetPasswordTokenPurpose );
        }

        /// <summary>
        /// 通过手机号重置密码
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="token">令牌</param>
        /// <param name="newPassword">新密码</param>
        public async Task ResetPasswordByPhoneAsync( User user, string token, string newPassword ) {
            var result = await Manager.ResetPasswordAsync( user, TokenOptions.DefaultPhoneProvider, token, newPassword );
            result.ThrowIfError();
        }

        #endregion

        #region 修改密码

        /// <summary>
        /// 修改密码
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="currentPassword">当前密码</param>
        /// <param name="newPassword">新密码</param>
        public async Task ChangePasswordAsync( User user, string currentPassword, string newPassword ) {
            var result = await Manager.ChangePasswordAsync( user, currentPassword, newPassword );
            result.ThrowIfError();
        }

        /// <summary>
        /// 修改密码
        /// </summary>
        /// <param name="user">用户</param>
        /// <param name="newPassword">新密码</param>
        public async Task ChangePasswordAsync( User user, string newPassword ) {
            var result = await Manager.UpdatePasswordAsync( user, newPassword );
            result.ThrowIfError();
        }

        #endregion

        #region 查找用户

        /// <summary>
        /// 通过用户名查找
        /// </summary>
        /// <param name="userName">用户名</param>
        public async Task<User> FindByNameAsync( string userName ) {
            return await Manager.FindByNameAsync( userName );
        }

        /// <summary>
        /// 通过电子邮件查找
        /// </summary>
        /// <param name="email">电子邮件</param>
        public async Task<User> FindByEmailAsync( string email ) {
            return await Manager.FindByEmailAsync( email );
        }

        /// <summary>
        /// 通过手机号查找
        /// </summary>
        /// <param name="phoneNumber">手机号</param>
        public async Task<User> FindByPhoneAsync( string phoneNumber ) {
            return await UserRepository.SingleAsync( t => t.PhoneNumber == phoneNumber );
        }

        #endregion
    }
}
