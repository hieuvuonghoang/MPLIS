//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MPLIS.Libraries.Data.SSOCore.DbModels
{
    using System;
    using System.Collections.Generic;
    
    public partial class HT_TOCHUC_NGUOIDUNG
    {
        public string TOCHUCID { get; set; }
        public string NGUOIDUNGID { get; set; }
        public string CHUCVU { get; set; }
        public string uId { get; set; }
        public Nullable<System.DateTime> THOIDIEMKHOITAO { get; set; }
        public string NGUOICAPNHATID { get; set; }
        public Nullable<System.DateTime> THOIDIEMCAPNHAT { get; set; }
    
        public virtual HT_NGUOIDUNG HT_NGUOIDUNG { get; set; }
        public virtual HT_TOCHUC HT_TOCHUC { get; set; }
    }
}
