﻿//------------------------------------------------------------------------------
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
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    
    public partial class MPLISEntities : DbContext
    {
        public MPLISEntities()
            : base("name=MPLISEntities")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<HC_DMKVHC> HC_DMKVHC { get; set; }
        public virtual DbSet<HC_HUYEN> HC_HUYEN { get; set; }
        public virtual DbSet<HC_TINH> HC_TINH { get; set; }
        public virtual DbSet<HC_TINHTHAMSO> HC_TINHTHAMSO { get; set; }
        public virtual DbSet<HT_CAUHINH> HT_CAUHINH { get; set; }
        public virtual DbSet<HT_CAUHINHNGUOIDUNG> HT_CAUHINHNGUOIDUNG { get; set; }
        public virtual DbSet<HT_CHUCNANG> HT_CHUCNANG { get; set; }
        public virtual DbSet<HT_CHUCNANG_NHOMCHUCNANG> HT_CHUCNANG_NHOMCHUCNANG { get; set; }
        public virtual DbSet<HT_LICHSUTRUYCAP> HT_LICHSUTRUYCAP { get; set; }
        public virtual DbSet<HT_MAUGIAYTOKEMTHEOHS> HT_MAUGIAYTOKEMTHEOHS { get; set; }
        public virtual DbSet<HT_MENU> HT_MENU { get; set; }
        public virtual DbSet<HT_NGUOIDUNG> HT_NGUOIDUNG { get; set; }
        public virtual DbSet<HT_NGUOIDUNG_QUYEN> HT_NGUOIDUNG_QUYEN { get; set; }
        public virtual DbSet<HT_NHOMCHUCNANG> HT_NHOMCHUCNANG { get; set; }
        public virtual DbSet<HT_NHOMCHUCNANG_MENU> HT_NHOMCHUCNANG_MENU { get; set; }
        public virtual DbSet<HT_QUYEN> HT_QUYEN { get; set; }
        public virtual DbSet<HT_THONGBAO> HT_THONGBAO { get; set; }
        public virtual DbSet<HT_TOCHUC> HT_TOCHUC { get; set; }
        public virtual DbSet<HT_TOCHUC_NGUOIDUNG> HT_TOCHUC_NGUOIDUNG { get; set; }
        public virtual DbSet<HT_TOCHUC_NHOMCHUCNANG> HT_TOCHUC_NHOMCHUCNANG { get; set; }
        public virtual DbSet<HT_UNGDUNG> HT_UNGDUNG { get; set; }
        public virtual DbSet<HT_XA_NGUOIDUNG> HT_XA_NGUOIDUNG { get; set; }
        public virtual DbSet<HT_XA_TOCHUC> HT_XA_TOCHUC { get; set; }
        public virtual DbSet<HS_HOSO> HS_HOSO { get; set; }
        public virtual DbSet<HS_LIENKETTHUADAT> HS_LIENKETTHUADAT { get; set; }
        public virtual DbSet<HS_THANHPHANHOSO> HS_THANHPHANHOSO { get; set; }
        public virtual DbSet<HS_LICHSU> HS_LICHSU { get; set; }
    }
}
