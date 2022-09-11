using System;
using System.Collections.Generic;
using System.Text;
using Domain;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Webapp.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Student> Students { get; set; }
        public DbSet<Homework> Homeworks { get; set; }
        public DbSet<Grade> Grades { get; set; }
        
        public DbSet<CesareVigenere> CesareVigeneres { get; set; }

        public DbSet<DiffieHellmanPoco> DiffieHellmans { get; set; }

        public DbSet<RsaEncryptPoco> RsaEncrypts { get; set; }
    }
}