using System;

namespace ConsoleApp
{
    public class ConsoleUtils
    {
        public static string GetInput(string message)
        {
            Console.WriteLine(message);
            Console.Write(">");

            return Console.ReadLine()?.Trim();
        }
    }
}