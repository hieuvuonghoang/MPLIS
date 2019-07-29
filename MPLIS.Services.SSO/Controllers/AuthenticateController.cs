using MPLIS.Libraries.Data.SSO.Models;
using MPLIS.Libraries.Data.SSO.Params;
using MPLIS.Library.Data.SSO.BuModels;
using MPLIS.Library.Services.SSO;
using MPLIS.Library.Services.SSO.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MPLIS.Services.SSO.Controllers
{
    public class AuthenticateController : Controller
    {
        // GET: Authenticate
        public ActionResult Login()
        {
            SSOLoginMessage tm = null;
            SSOUserLoginInfors ui = null;
            string tk = null;
            var par = SSOHTTPRequestService.GetRequestParams(Request);
            ViewBag.ReturnUrl = par == null ? "" : (par.ReturnUrl == null ? "" : par.ReturnUrl);
            if (par != null && par.Token != null && !par.Token.Equals(""))
            {
                if (UserManagerService.TokenMessage.TryRemove(par.Token, out tm))
                    ViewBag.TB = tm.Message;

                if (UserManagerService.UsersLoggedIn.TryRemove(par.Token, out ui))
                    UserManagerService.UserToken.TryRemove(ui.User.TENDANGNHAP, out tk);
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(FormCollection ketNoiForm)
        {
            string thongBao = "";
            // Lay gia tri tu trang html
            string username = ketNoiForm["txtemail"].Trim();
            string password = ketNoiForm["txtpassword"];
            string ghiNhoTaikhoan = ketNoiForm["chkGhiNhoTaikhoan"];
            string ReturnUrl = ketNoiForm["txtReturnUrl"];
            // mã hóa password            
            var sha = SHA256.Create();
            string aa = "";

            if (password != null && username != null)
            {
                var computedHash = sha.ComputeHash(Encoding.Unicode.GetBytes(password));
                aa = Convert.ToBase64String(computedHash).ToString();
                // Kiem tra Mat Khau co duoc lay ra tu nut ghi nho mat khau
                if (password.Length > 15)
                {
                    if (password.Substring(0, 15) == "H1@iN9inhmpl8i6")
                    {
                        if (password.Length >= 45)
                        {
                            aa = password.Substring(30, 15) + password.Substring(15, 15) + password.Substring(45);
                        }
                    }
                }

                SSOUserLoginInfors Us = UserManagerService.AuthenticateUser(username, aa, ref thongBao);
                if (Us != null)
                {
                    if (Us.ToChuc == null)
                    {
                        thongBao = "Tổ chức của người dùng không tồn tại. Vui lòng liên hệ với Admin";
                    }
                    else
                    {
                        if (ghiNhoTaikhoan != null)
                        {
                            Response.Cookies["userName"].Value = username;
                            Response.Cookies["userName"].Expires = DateTime.Now.AddDays(10);
                            Response.Cookies["passNguoiDung"].Value = aa.Substring(15, 15) + aa.Substring(0, 15) + aa.Substring(30);
                            Response.Cookies["passNguoiDung"].Expires = DateTime.Now.AddDays(10);
                        }
                        //Session["RequestParams"] = par;
                        //var par = (SSOHttpRequestParams)Session["RequestParams"];// SSOHTTPRequestService.GetRequestParams(Request);
                        string redirectUrl = UriUtil.RemoveParameter(ReturnUrl, SSOConstants.UrlParams.TOKEN);
                        redirectUrl = Utility.GetAppendedQueryString(redirectUrl, SSOConstants.UrlParams.TOKEN, Us.Token);
                        redirectUrl += "&NGUOIDUNGID=" + Us.User.NGUOIDUNGID;
                        //System.Web.HttpContext.Current.Response.Redirect("");
                        HttpCookie aCookie = new HttpCookie(SSOConstants.Cookie.AUTH_COOKIE);//("VILISUserLoginInfo");
                        aCookie.Value = Us.UserCookie.Value;
                        //đặt timeout của cookie bằng với giá trị timeout của token
                        aCookie.Expires = DateTime.Now.AddHours(Config.AUTH_TOKEN_TIMEOUT_IN_HOURS);
                        Response.Cookies.Add(aCookie);
                        return Redirect(redirectUrl);
                    }
                }
                else
                {
                    ViewBag.ReturnUrl = ReturnUrl;
                    ViewBag.TB = thongBao;
                }
            }
            return View();
        }
    }
}