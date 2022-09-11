using System;
using System.Collections.Generic;

namespace Domain
{
    public class Student
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }

        public ICollection<Grade> Grades { get; set; }
    }
}