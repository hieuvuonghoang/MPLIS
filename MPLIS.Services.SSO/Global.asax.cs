using MPLIS.Libraries.Data.SSO.Models;
using MPLIS.Libraries.Data.SSO.Params;
using MPLIS.Library.Services.SSO;
using MPLIS.Library.Services.SSO.Services;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace MPLIS.Services.SSO
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            AutoMapperStartup.Execute();

            var oSession = new Thread(UserManagerService.checkAndReleaseUserInfo);

            // Start the session check thread
            oSession.Start();
        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            HttpApplication app = (HttpApplication)sender;
            var request = app.Request;

            //với post request thì không cần kiểm tra - phục vụ login POST request
            if (request.HttpMethod == "POST") return;

            //nếu là request tới wep api service thì tự động bỏ qua kiểm tra, tiếp tục xử lý
            if (request.Url.AbsolutePath.Contains("/api/")) return;

            //Lấy thông tin xác thực từ request
            SSOHttpRequestParams par = SSOHTTPRequestService.GetRequestParams(request);

            //ngừng xử lý request do không xác định được return url sau khi xác thực
            if (par == null || par.ReturnUrl == null || par.ReturnUrl.Equals(""))
            {
                Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy") + ": ngừng xử lý request do không xác định được return url sau khi xác thực");
                Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy") + JsonConvert.SerializeObject(par));
                app.CompleteRequest();
                return;
            }

            //Chỉ xử lý cho login, logout request, nếu không phải thì ngừng xử lý
            if (par.Action == null || !(par.Action.Equals(SSOConstants.ParamValues.LOGIN) || par.Action.Equals(SSOConstants.ParamValues.LOGOUT)))
            {
                Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy") + ": Chỉ xử lý cho login, logout request, nếu không phải thì ngừng xử lý");
                app.CompleteRequest();
                return;
            }

            //Logout
            if (par.Action.Equals(SSOConstants.ParamValues.LOGOUT))
            {
                Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy") + ": Logout request");
                UserManagerService.LogoutUser(par, SSOConstants.Cookie.AUTH_COOKIE, app);
                //Redirect user to default page
                SSOHTTPRequestService.Redirect(par.ReturnUrl, "", app);
                app.CompleteRequest();
                return;
            }

            //Nếu là post back thì tiếp tục xử lý như bình thường - dùng cho login page post back
            //if (HttpContext.Current.Request.HttpMethod == "POST") return;

            //Session["RequestParams"] = par;

            //Yêu cầu login hoặc chưa xác thực, tiếp tục xử lý xác thực như bình thường
            if (par.Token == null || par.Token.Equals("")) return;

            //Xử lý cho trường hợp request đã xác thực, gửi lại token và redirect người dùng về trang yêu cầu
            //Nếu chưa xác thực, mở trang login phục vụ xác thực trước khi redirect tới trang yêu cầu
            SSOUserLoginInfors Us = null;
            if (UserManagerService.CheckRequestAuthentication(par.Token, out Us))
            {
                Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss") + ": đã xác thực, ngừng xử lý");
                app.Response.Cookies.Add(Us.UserCookie);
                Us.FirstTimeToken = true;
                UserManagerService.UsersLoggedIn.AddOrUpdate(Us.Token, Us,
                                (key, existingVal) =>
                                {
                                    existingVal.FirstTimeToken = Us.FirstTimeToken;
                                    return existingVal;
                                });
                SSOHTTPRequestService.Redirect(par.ReturnUrl, par.Token, app);
                app.CompleteRequest();
            }
        }
    }
}
