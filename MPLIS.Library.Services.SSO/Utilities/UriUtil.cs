using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace MPLIS.Library.Services.SSO
{
    public class UriUtil
    {
        public static string RemoveParameter(string url, string key)
        {
            var uri = new Uri(url);
            // this gets all the query string key value pairs as a collection
            var newQueryString = HttpUtility.ParseQueryString(uri.Query);

            // this removes the key if exists
            newQueryString.Remove(key);

            // this gets the page path from root without QueryString
            string pagePathWithoutQueryString = uri.GetLeftPart(UriPartial.Path);

            return newQueryString.Count > 0
                ? String.Format("{0}?{1}", pagePathWithoutQueryString, newQueryString)
                : pagePathWithoutQueryString;

            //url = url.ToLower();
            //key = key.ToLower();
            //if (HttpContext.Current.Request[key] == null) return url;

            //string fragmentToRemove = string.Format("{0}={1}", key, HttpContext.Current.Request[key].ToLower());

            //String result = url.ToLower().Replace("&" + fragmentToRemove, string.Empty).Replace("?" + fragmentToRemove, string.Empty);
            //return result;
        }

        public static string GetAbsolutePathForRelativePath(string relativePath)
        {
            HttpRequest Request = HttpContext.Current.Request;
            string returnUrl = string.Format("{0}{1}", Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, string.Empty), VirtualPathUtility.ToAbsolute(relativePath));
            return returnUrl;
        }
    }
}
