using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Net.Http;
using MPLIS.Libraries.Data.SSO.Models;
using Newtonsoft.Json;
using System.IO;
using System.Net.Http.Headers;
using System.Net;
using MPLIS.Libraries.Data.SSO.Params;

namespace MPLIS.Library.Services.SSO.Services
{
    public static class SSOHTTPRequestService
    {
        //Lấy thông tin xác thực từ request
        public static SSOHttpRequestParams GetRequestParams(HttpRequest Request)
        {
            SSOHttpRequestParams par = new SSOHttpRequestParams();
            HttpCookie aCookie = null;

            try
            {
                par.Action = Request.Params[SSOConstants.UrlParams.ACTION];
                par.ReturnUrl = Request.Params[SSOConstants.UrlParams.RETURN_URL];
                //par.Token = Request.Params[SSOConstants.UrlParams.TOKEN];

                aCookie = Request.Cookies[SSOConstants.Cookie.AUTH_COOKIE];
                if (aCookie != null)
                {
                    string encrString = aCookie.Value;
                    string decString = Utility.Decrypt(encrString, true, Config.SECURITY_KEY);
                    SSOCookieValues cv = JsonConvert.DeserializeObject<SSOCookieValues>(decString);
                    par.Token = cv.Token;
                }
            }
            catch (Exception ex)
            {
                Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy") + ": " + JsonConvert.SerializeObject(aCookie));
                Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy") + ": " + ex.ToString());
                par = null;
            }

            return par;
        }

        public static SSOHttpRequestParams GetRequestParams(HttpRequestBase Request)
        {
            SSOHttpRequestParams par = new SSOHttpRequestParams();
            par.Action = Request.Params[SSOConstants.UrlParams.ACTION];
            par.ReturnUrl = Request.Params[SSOConstants.UrlParams.RETURN_URL];
            par.Token = Request.Params[SSOConstants.UrlParams.TOKEN];

            if (par.Token == null)
            {
                HttpCookie aCookie = Request.Cookies[SSOConstants.Cookie.AUTH_COOKIE];
                if (aCookie != null)
                {
                    string encrString = aCookie.Value;
                    string decString = Utility.Decrypt(encrString, true, Config.SECURITY_KEY);
                    SSOCookieValues cv = JsonConvert.DeserializeObject<SSOCookieValues>(decString);
                    par.Token = cv.Token;
                }
            }

            return par;
        }

        public static bool CheckExpired(DateTime value)
        {
            return value.CompareTo(DateTime.Now) < 0;
        }

        /// <summary>
        /// Determines whether the Cookie is expired or not
        /// </summary>
        /// <param name="aCookie"></param>
        /// <returns></returns>
        public static bool CheckExpired(HttpCookie aCookie)
        {
            return aCookie.Expires.CompareTo(DateTime.Now) < 0;
        }

        /// <summary>
        /// Determines whether the Token is expired or not
        /// </summary>
        /// <param name="expirytime"></param>
        /// <returns></returns>
        public static bool CheckExpired(SSOUserLoginInfors Us)
        {
            return Us.TokenExpires.CompareTo(DateTime.Now) < 0;
        }

        /// <summary>
        /// Removes Cookie from the response
        /// </summary>
        /// <param name="Cookie"></param>
        public static void RemoveCookie(string CookieName, HttpResponse Response)
        {
            Response.Cookies.Remove(CookieName);

            HttpCookie myCookie = new HttpCookie(CookieName);
            myCookie.Expires = DateTime.Now.AddDays(-1d);
            Response.Cookies.Add(myCookie);
        }

        /// <summary>
        /// Append Token to the URl and redirect
        /// </summary>
        /// <param name="Url"></param>
        /// <param name="Token"></param>
        /// <param name="Response"></param>
        public static void Redirect(string Url, string Token, HttpApplication app)
        {
            string redirectUrl = Url;
            redirectUrl = UriUtil.RemoveParameter(redirectUrl, SSOConstants.UrlParams.TOKEN);
            if (Token != null && !Token.Equals("")) redirectUrl = Utility.GetAppendedQueryString(Url, SSOConstants.UrlParams.TOKEN, Token);

            app.Response.Redirect(redirectUrl, false);
            app.Response.StatusCode = 301;
        }

        #region "API support function"
        public static string getDataInRequest(HttpRequestMessage Request)
        {
            string ret = "";
            bool Rslt = false;

            MultipartMemoryStreamProvider prvdr = new MultipartMemoryStreamProvider();
            Task readData = Request.Content.ReadAsMultipartAsync(prvdr).ContinueWith((readTask) =>
            {
                Rslt = readTask.IsCompleted;
            });

            readData.Wait();
            if (Rslt)
            {
                foreach (HttpContent ctnt in prvdr.Contents)
                {
                    // You would get hold of the inner memory stream here
                    Stream stream = ctnt.ReadAsStreamAsync().Result;

                    var sr = new StreamReader(stream);
                    var myStr = sr.ReadToEnd();
                    if (myStr != null && !myStr.Equals(""))
                    {
                        ret = Utility.Decrypt(myStr, true, Config.SECURITY_KEY);
                        break;
                    }
                }
            }

            return ret;
        }

        //Lấy dữ liệu từ string được gửi từ client
        public static T getDataFromString<T>(string input)
        {
            T ret;
            SsoApiServiceData data;

            try
            {
                data = JsonConvert.DeserializeObject<SsoApiServiceData>(input);
                if (checkReturnData(data))
                    ret = JsonConvert.DeserializeObject<T>(data.Value);
                else
                    ret = default(T);
            }
            catch (Exception ex)
            {
                ret = default(T);
            }

            return ret;
        }

        private static bool checkReturnData(SsoApiServiceData data)
        {
            if (data == null || data.TimeValid == null) return false;

            Utility.WriteToLogFile(DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss") + ": checkReturnData - " + (data.TimeValid.CompareTo(DateTime.Now) > 0).ToString());
            return data.TimeValid.CompareTo(DateTime.Now) > 0;
        }

        //Chuẩn bị dữ liệu trả về web nghiệp vụ
        //Tạo hai lớp bọc quanh tham số và mã hóa dữ liệu chuyển
        private static StreamContent prepareData(object data)
        {
            //MultipartFormDataContent ret = new MultipartFormDataContent();
            StreamContent ret;

            //Tạo tham số cho service 
            string retString = JsonConvert.SerializeObject(data);
            SsoApiServiceData par = new SsoApiServiceData();
            par.TimeValid = DateTime.Now.AddMinutes(Config.AUTH_REQUEST_DATA_TIMEOUT_IN_MINUTES);
            par.Value = retString;
            retString = JsonConvert.SerializeObject(par);

            //Mã hóa và tạo đối tượng chuyển dữ liệu
            string encrString = Utility.Encrypt(retString, true, Config.SECURITY_KEY);
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(encrString);
            writer.Flush();
            stream.Position = 0;
            ret = new StreamContent(stream);

            return ret;
        }

        public static HttpResponseMessage CreateResponseMessage(object data, HttpStatusCode code)
        {
            HttpResponseMessage result = null;

            //MultipartFormDataContent ct = SSOHTTPRequestService.prepareData(data);
            StreamContent ct = SSOHTTPRequestService.prepareData(data);
            result = new HttpResponseMessage(code);
            result.Content = ct;
            result.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/octet-stream");
            result.Content.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment");
            result.Content.Headers.ContentDisposition.FileName = "SSO.MPLIS";

            return result;
        }
        #endregion
    }
}
