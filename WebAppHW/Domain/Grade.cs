namespace Domain
{
    public class Grade
    {
        public int Id { get; set; } // PK
        public int GradeValue { get; set; }


        public int StudentId { get; set; } // FK
        public Student Student { get; set; }

        public int HomeworkId { get; set; } // FK
        public Homework Homework { get; set; }
    }
}