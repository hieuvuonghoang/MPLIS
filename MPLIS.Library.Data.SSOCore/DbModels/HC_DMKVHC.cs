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
    
    public partial class HC_DMKVHC
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public HC_DMKVHC()
        {
            this.HT_XA_NGUOIDUNG = new HashSet<HT_XA_NGUOIDUNG>();
            this.HT_XA_TOCHUC = new HashSet<HT_XA_TOCHUC>();
            this.HS_HOSO = new HashSet<HS_HOSO>();
            this.HS_LIENKETTHUADAT = new HashSet<HS_LIENKETTHUADAT>();
            this.HS_LICHSU = new HashSet<HS_LICHSU>();
        }
    
        public string KVHCID { get; set; }
        public string HUYENID { get; set; }
        public string MAXA { get; set; }
        public string TENKVHC { get; set; }
        public string PHANLOAI { get; set; }
        public string THUTUSAPXEP { get; set; }
        public string uId { get; set; }
        public Nullable<System.DateTime> THOIDIEMKHOITAO { get; set; }
        public string NGUOICAPNHATID { get; set; }
        public Nullable<System.DateTime> THOIDIEMCAPNHAT { get; set; }
        public string MAKVHC { get; set; }
    
        public virtual HC_HUYEN HC_HUYEN { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HT_XA_NGUOIDUNG> HT_XA_NGUOIDUNG { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HT_XA_TOCHUC> HT_XA_TOCHUC { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HS_HOSO> HS_HOSO { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HS_LIENKETTHUADAT> HS_LIENKETTHUADAT { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HS_LICHSU> HS_LICHSU { get; set; }
    }
}