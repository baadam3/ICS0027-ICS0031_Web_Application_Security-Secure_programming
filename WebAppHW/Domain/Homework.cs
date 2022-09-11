using System;
using System.Collections.Generic;

namespace Domain
{
    public class Homework
    {
        public int Id { get; set; }
        public string Description { get; set; }

        public ICollection<Grade> Grades { get; set; }
    }
}