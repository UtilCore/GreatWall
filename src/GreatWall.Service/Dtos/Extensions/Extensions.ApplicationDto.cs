﻿using System.Linq;
using GreatWall.Data.Pos;
using GreatWall.Data.Pos.Models;
using GreatWall.Domain.Enums;
using GreatWall.Domain.Models;
using Util.Helpers;
using Util.Maps;

namespace GreatWall.Service.Dtos.Extensions {
    /// <summary>
    /// 应用程序参数扩展
    /// </summary>
    public static partial class Extension {
        /// <summary>
        /// 转成应用程序参数
        /// </summary>
        public static ApplicationDto ToDto( this ApplicationPo po ) {
            if( po == null )
                return null;
            var result = po.MapTo<ApplicationDto>();
            var extend = Json.ToObject<ApplicationExtend>( po.Extend );
            if ( extend == null )
                return result;
            extend.MapTo( result );
            if ( extend.IsClient ) {
                extend.Client.MapTo( result );
                result.RedirectUri = extend.Client.RedirectUris.FirstOrDefault();
                result.PostLogoutRedirectUri = extend.Client.PostLogoutRedirectUris.FirstOrDefault();
            }
            return result;
        }

        /// <summary>
        /// 转成应用程序实体
        /// </summary>
        public static Application ToEntity( this ApplicationDto dto ) {
            if ( dto == null )
                return null;
            var result = dto.MapTo<Application>();
            dto.MapTo( result.Client );
            result.IsClient = dto.ApplicationType == ApplicationType.Client;
            result.Client.RedirectUris.Add( dto.RedirectUri );
            result.Client.PostLogoutRedirectUris.Add( dto.PostLogoutRedirectUri );
            return result;
        }
    }
}