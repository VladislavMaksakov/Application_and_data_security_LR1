using System;
using System.Collections.Generic;
using System.Linq; // Необхідно для використання методів .Any()
using System.Text.RegularExpressions; // Необхідно для роботи з Regex

namespace PasswordSecurityAudit
{
   class Program
   {
      static void Main(string[] args)
      {
         // --- НАЛАШТУВАННЯ КОНСОЛІ ---
         // Встановлюємо кодування UTF-8, щоб українські літери (і, ї, є, ґ) відображалися коректно
         Console.OutputEncoding = System.Text.Encoding.UTF8;

         Console.WriteLine("ЛР1 Максаков Владислав");

         // --- ОСНОВНИЙ ЦИКЛ ПРОГРАМИ ---
         // while (true) створює нескінченний цикл, щоб програма не закривалася після однієї перевірки
         while (true)
         {
            Console.WriteLine("\nВведіть ваші дані для аналізу:");

            // --- ВВЕДЕННЯ ДАНИХ ---
            Console.Write("Ім'я: ");
            // ?.Trim() безпечно видаляє зайві пробіли (наприклад, якщо користувач випадково натиснув пробіл)
            string name = Console.ReadLine()?.Trim();

            Console.Write("Дата народження (дд.мм.рррр): ");
            string dobInput = Console.ReadLine()?.Trim();

            Console.Write("Пароль для перевірки: ");
            string password = Console.ReadLine()?.Trim();

            // --- ВАЛІДАЦІЯ (ПЕРЕВІРКА) ВВЕДЕННЯ ---
            // Якщо пароль порожній або null, просимо ввести знову
            if (string.IsNullOrEmpty(password))
            {
               Console.WriteLine("Пароль не може бути порожнім.");
               continue; // Повертає на початок циклу while
            }

            // --- ВИКЛИК ФУНКЦІЇ АНАЛІЗУ ---
            // Отримуємо результат у вигляді кортежу (Score, Recommendations)
            var report = AnalyzePassword(password, name, dobInput);

            // --- ВИВЕДЕННЯ РЕЗУЛЬТАТІВ ---
            Console.WriteLine(new string('-', 40)); // Малює розділювальну лінію
            Console.WriteLine($"Оцінка безпеки: {report.Score}/10");

            // Тернарний оператор для визначення текстового рівня (Високий/Середній/Низький)
            string level = report.Score >= 8 ? "ВИСОКИЙ" : (report.Score >= 5 ? "СЕРЕДНІЙ" : "НИЗЬКИЙ");
            Console.WriteLine($"Рівень надійності: {level}");

            Console.WriteLine("Рекомендації:");

            // Перебір списку рекомендацій і виведення кожної з нового рядка
            foreach (var rec in report.Recommendations)
            {
               Console.WriteLine($"[!] {rec}");
            }

            // Якщо список рекомендацій порожній, значить пароль ідеальний
            if (report.Recommendations.Count == 0)
               Console.WriteLine("[OK] Чудовий пароль! Зауважень немає.");

            Console.WriteLine(new string('-', 40));

            // --- ПЕРЕВІРКА НА ВИХІД ---
            Console.Write("Перевірити інший пароль? (y/n): ");
            // Якщо натиснуто будь-яку клавішу, крім 'Y', цикл переривається і програма завершується
            if (Console.ReadKey().Key != ConsoleKey.Y) break;
            Console.WriteLine();
         }
      }

      // --- ЛОГІКА АНАЛІЗУ ---
      // Метод повертає кортеж (Tuple): ціле число (Score) та список рядків (List<string>)
      static (int Score, List<string> Recommendations) AnalyzePassword(string pwd, string name, string dob)
      {
         int score = 0;
         var recommendations = new List<string>();

         // --- АНАЛІЗ СТРУКТУРИ ПАРОЛЯ (LINQ) ---
         // .Any(...) перевіряє, чи є в рядку хоча б один символ, що відповідає умові
         bool hasUpper = pwd.Any(char.IsUpper);       // Чи є великі літери?
         bool hasLower = pwd.Any(char.IsLower);       // Чи є малі літери?
         bool hasDigit = pwd.Any(char.IsDigit);       // Чи є цифри?
         // Перевіряємо на спецсимволи (все, що не є літерою і не цифрою)
         bool hasSpecial = pwd.Any(ch => !char.IsLetterOrDigit(ch));

         // --- НАРАХУВАННЯ БАЛІВ ЗА СКЛАДНІСТЬ ---
         if (pwd.Length >= 8) score += 2;   // Базовий бал за довжину
         if (pwd.Length >= 12) score += 2;  // Бонус за довгий пароль
         else recommendations.Add("Збільште довжину пароля (мінімум 12 символів).");

         // Додаємо бали за кожен тип символів, якщо його немає — додаємо рекомендацію
         if (hasUpper) score += 1; else recommendations.Add("Додайте великі літери (A-Z).");
         if (hasLower) score += 1; else recommendations.Add("Додайте маленькі літери (a-z).");
         if (hasDigit) score += 2; else recommendations.Add("Додайте цифри (0-9).");
         if (hasSpecial) score += 2; else recommendations.Add("Додайте спеціальні символи (!@#$%).");

         // --- ПЕРЕВІРКА НА ПЕРСОНАЛЬНІ ДАНІ (ІМ'Я) ---
         // StringComparison.OrdinalIgnoreCase дозволяє знайти "Ivan" навіть якщо введено "ivan" або "IVAN"
         if (!string.IsNullOrEmpty(name) && pwd.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
         {
            score -= 5; // Великий штраф за використання імені
            recommendations.Add("КРИТИЧНО: Пароль містить ваше ім'я. Приберіть його.");
         }

         // --- ПЕРЕВІРКА НА ДАТУ НАРОДЖЕННЯ ---
         if (!string.IsNullOrEmpty(dob) && dob.Length >= 4)
         {
            // Використовуємо Regex (регулярний вираз) для пошуку 4 цифр підряд (\d{4}) - це рік
            var yearMatch = Regex.Match(dob, @"\d{4}");

            // Якщо рік знайдено в даті народження І цей рік є в паролі
            if (yearMatch.Success && pwd.Contains(yearMatch.Value))
            {
               score -= 4; // Штраф за рік
               recommendations.Add($"КРИТИЧНО: Пароль містить рік вашого народження ({yearMatch.Value}).");
            }
            // Перевірка на повне співпадіння дати (наприклад "12.05.2000")
            if (pwd.Contains(dob))
            {
               score -= 5;
               recommendations.Add("КРИТИЧНО: Пароль містить вашу повну дату народження.");
            }
         }

         // --- НОРМАЛІЗАЦІЯ ОЦІНКИ ---
         // Обмежуємо оцінку в межах від 1 до 10 (щоб не було від'ємних значень або більше 10)
         if (score < 1) score = 1;
         if (score > 10) score = 10;

         // Повертаємо результат
         return (score, recommendations);
      }
   }
}