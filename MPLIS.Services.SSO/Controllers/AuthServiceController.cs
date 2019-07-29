using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using MPLIS.Libraries.Data.SSOCore.DbModels;
using MPLIS.Library.Services.SSO.Services;
using MPLIS.Library.Services.SSO;
using System.Web;
using System.Web.Http.Cors;
using Newtonsoft.Json;
using System.IO;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Text;
using MPLIS.Libraries.Data.SSO.Models;
using MPLIS.Library.Data.SSO.BuModels;
using MPLIS.Libraries.Data.SSO.Params;

namespace MPLIS.Services.SSO.Controllers
{
    public class AuthServiceController : ApiController
    {
        [AcceptVerbs("POST")]
        //[EnableCors(origins: "*", headers: "*", methods: "*")]
        public HttpResponseMessage getUserInfors()
        {
            SSOUserLoginInfors Us = null, ret = null;

            string req = SSOHTTPRequestService.getDataInRequest(Request);
            SSOHtTokenRequestData Data = SSOHTTPRequestService.getDataFromString<SSOHtTokenRequestData>(req);
            bool check = false;

            if (UserManagerService.CheckRequestAuthentication(Data.Token, out Us))
                if (Data.isTokenFromCookie || Us.FirstTimeToken)
                {
                    ret = AutoMapper.Mapper.Map<SSOUserLoginInfors, SSOUserLoginInfors>(Us);
                    ret.SuccessGetData = true;
                    ret.ThongBao = "Lấy dữ liệu thành công";
                    ret.UserCookie = null;
                    ret.FirstTimeToken = false;
                    Us.FirstTimeToken = false;
                    UserManagerService.UsersLoggedIn.AddOrUpdate(Us.Token, Us,
                                (key, existingVal) =>
                                {
                                    existingVal.FirstTimeToken = Us.FirstTimeToken;
                                    return existingVal;
                                });
                    check = true;
                }

            if (!check)
            {
                ret = new SSOUserLoginInfors();
                ret.SuccessGetData = false;
                ret.ThongBao = "Yêu cầu không hợp lệ";
            }

            return SSOHTTPRequestService.CreateResponseMessage(ret, HttpStatusCode.OK);
        }

        [AcceptVerbs("POST")]
        //[EnableCors(origins: "*", headers: "*", methods: "*")]
        public HttpResponseMessage getUserStatus()
        {
            SSOUserStatus us = new SSOUserStatus();
            SSOUserLoginInfors Us = null;

            string req = SSOHTTPRequestService.getDataInRequest(Request);
            string dt = SSOHTTPRequestService.getDataFromString<string>(req);

            us.UserLoggedIn = UserManagerService.CheckRequestAuthentication(dt, out Us);

            return SSOHTTPRequestService.CreateResponseMessage(us, HttpStatusCode.OK);
        }

        [MimeMultipart]
        [AcceptVerbs("POST")]
        //[EnableCors(origins: "*", headers: "*", methods: "*")]
        public HttpResponseMessage UpdateCookie()
        {
            SSOReturnResult ret = new SSOReturnResult();
            SSOUserStatus us = new SSOUserStatus();

            string req = SSOHTTPRequestService.getDataInRequest(Request);
            SSOCookieInfor ci = SSOHTTPRequestService.getDataFromString<SSOCookieInfor>(req);
            SSOUserLoginInfors oldValue = null;

            if (ci != null && ci.Token != null && UserManagerService.CheckRequestAuthentication(ci.Token, out oldValue))
            {
                oldValue.UserCookie.Expires = ci.Expires;
                UserManagerService.UsersLoggedIn.AddOrUpdate(ci.Token, oldValue,
                    (key, existingVal) =>
                    {
                        existingVal.UserCookie.Expires = oldValue.UserCookie.Expires;
                        return existingVal;
                    });

                ret.ReturnCode = HttpStatusCode.OK;
                ret.Message = "Cập nhật thành công";
            }
            else
            {
                ret.ReturnCode = HttpStatusCode.BadRequest;
                ret.Message = "Dữ liệu cập nhật không hợp lệ";
            }

            return SSOHTTPRequestService.CreateResponseMessage(ret, HttpStatusCode.OK);
        }

        [AcceptVerbs("POST")]
        //[EnableCors(origins: "*", headers: "*", methods: "*")]
        public HttpResponseMessage LogoutUser(string Token)
        {
            SSOUserLoginInfors Us = null;

            if (UserManagerService.CheckRequestAuthentication(Token, out Us))
            {
                var context = new HttpContextWrapper(HttpContext.Current);
                HttpRequestBase request = context.Request;
                SSOHttpRequestParams par = SSOHTTPRequestService.GetRequestParams(request);
                //var app = HttpContext.Current.ApplicationInstance as HttpApplication;
                UserManagerService.LogoutUser(par, SSOConstants.Cookie.AUTH_COOKIE, null);
            }

            SSOReturnResult ret = new SSOReturnResult();
            ret.ReturnCode = HttpStatusCode.OK;
            ret.Message = "Logout thành công";

            return SSOHTTPRequestService.CreateResponseMessage(ret, HttpStatusCode.OK);
        }

        /// <summary>
        /// Authenticates user by UserName and Password
        /// </summary>
        /// <param name="UserName"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        //public HttpResponseMessage Authenticate(string UserName, string Password)
        //{
        //    HttpResponseMessage result;
        //    string ThongBao = "";
        //    UserLoginInfors Us = UserManagerService.AuthenticateUser(UserName, Password, ref ThongBao);
        //    if (Us != null)
        //    {
        //        Us.SuccessGetData = true;
        //        //Us.ThongBao = "Lấy dữ liệu thành công";
        //    }
        //    else
        //    {
        //        Us = new UserLoginInfors();
        //        Us.SuccessGetData = false;
        //        //Us.ThongBao = "Token không hợp lệ";
        //    }

        //    result = new HttpResponseMessage(HttpStatusCode.OK);
        //    string retString = JsonConvert.SerializeObject(Us);
        //    string encrString = Utility.Encrypt(retString, true, Config.SECURITY_KEY);
        //    MemoryStream stream = new MemoryStream();
        //    StreamWriter writer = new StreamWriter(stream);
        //    writer.Write(encrString);
        //    writer.Flush();
        //    stream.Position = 0;
        //    result.Content = new StreamContent(stream);
        //    result.Content.Headers.ContentType =
        //        new MediaTypeHeaderValue("application/octet-stream");
        //    result.Content.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment");
        //    result.Content.Headers.ContentDisposition.FileName = "UI.MPLIS";

        //    return result;
        //}
    }
}
