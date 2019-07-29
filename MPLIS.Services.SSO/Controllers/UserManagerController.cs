using MPLIS.Libraries.Data.SSO.Models;
using MPLIS.Library.Services.SSO.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace MPLIS.Services.SSO.Controllers
{
    public class UserManagerController : ApiController
    {
        //Cập nhật thông tin người dùng
        public HttpResponseMessage UpdateUser()
        {
            string message = "";
            bool isSuccess = false;
            string req = SSOHTTPRequestService.getDataInRequest(Request);
            SSOHtNguoiDung us = SSOHTTPRequestService.getDataFromString<SSOHtNguoiDung>(req);

            if (us != null)
            {
                isSuccess = UserManagerService.UpdateUser(us, out message);
            }

            if (isSuccess)
                return SSOHTTPRequestService.CreateResponseMessage(message, HttpStatusCode.OK);
            else
                return SSOHTTPRequestService.CreateResponseMessage(message, HttpStatusCode.InternalServerError);
        }

        // GET api/<controller>
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/<controller>/5
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<controller>
        public void Post([FromBody]string value)
        {
        }

        // PUT api/<controller>/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/<controller>/5
        public void Delete(int id)
        {
        }
    }
}