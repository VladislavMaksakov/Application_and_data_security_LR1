using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PasswordSecurityAudit
{
   class Program
   {
      static void Main(string[] args)
      {
         Console.OutputEncoding = System.Text.Encoding.UTF8;
         Console.WriteLine("ЛР1 Максаков Владислав");

         while (true)
         {
            Console.WriteLine("\nВведіть ваші дані для аналізу:");
            Console.Write("Ім'я: ");
            string name = Console.ReadLine()?.Trim();
            Console.Write("Дата народження (дд.мм.рррр): ");
            string dobInput = Console.ReadLine()?.Trim();
            Console.Write("Пароль для перевірки: ");
            string password = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(password))
            {
               Console.WriteLine("Пароль не може бути порожнім.");
               continue;
            }

            var report = AnalyzePassword(password, name, dobInput);
            Console.WriteLine(new string('-', 40));
            Console.WriteLine($"Оцінка безпеки: {report.Score}/10");
            string level = report.Score >= 8 ? "ВИСОКИЙ" : (report.Score >= 5 ? "СЕРЕДНІЙ" : "НИЗЬКИЙ");
            Console.WriteLine($"Рівень надійності: {level}");
            Console.WriteLine("Рекомендації:");

            foreach (var rec in report.Recommendations)
            {
               Console.WriteLine($"[!] {rec}");
            }

            if (report.Recommendations.Count == 0)
               Console.WriteLine("[OK] Чудовий пароль! Зауважень немає.");

            Console.WriteLine(new string('-', 40));
            Console.Write("Перевірити інший пароль? (y/n): ");
            if (Console.ReadKey().Key != ConsoleKey.Y) break;
            Console.WriteLine();
         }
      }

      static (int Score, List<string> Recommendations) AnalyzePassword(string pwd, string name, string dob)
      {
         int score = 0;
         var recommendations = new List<string>();
         bool hasUpper = pwd.Any(char.IsUpper);
         bool hasLower = pwd.Any(char.IsLower);
         bool hasDigit = pwd.Any(char.IsDigit);
         bool hasSpecial = pwd.Any(ch => !char.IsLetterOrDigit(ch));

         if (pwd.Length >= 8) score += 2;
         if (pwd.Length >= 12) score += 2;
         else recommendations.Add("Збільште довжину пароля (мінімум 12 символів).");
         if (hasUpper) score += 1; else recommendations.Add("Додайте великі літери (A-Z).");
         if (hasLower) score += 1; else recommendations.Add("Додайте маленькі літери (a-z).");
         if (hasDigit) score += 2; else recommendations.Add("Додайте цифри (0-9).");
         if (hasSpecial) score += 2; else recommendations.Add("Додайте спеціальні символи (!@#$%).");

         if (!string.IsNullOrEmpty(name) && pwd.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
         {
            score -= 5;
            recommendations.Add("КРИТИЧНО: Пароль містить ваше ім'я. Приберіть його.");
         }

         if (!string.IsNullOrEmpty(dob) && dob.Length >= 4)
         {
            var yearMatch = Regex.Match(dob, @"\d{4}");
            if (yearMatch.Success && pwd.Contains(yearMatch.Value))
            {
               score -= 4;
               recommendations.Add($"КРИТИЧНО: Пароль містить рік вашого народження ({yearMatch.Value}).");
            }
            if (pwd.Contains(dob))
            {
               score -= 5;
               recommendations.Add("КРИТИЧНО: Пароль містить вашу повну дату народження.");
            }
         }
         if (score < 1) score = 1;
         if (score > 10) score = 10;
         return (score, recommendations);
      }
   }
}