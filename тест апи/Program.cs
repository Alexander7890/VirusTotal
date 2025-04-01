using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class VirusTotalScanner
{
    private static readonly string apiKey = "ed6d9fb1e478b95ca22fa51da52ecc6b24e3164de7be51a789037253ddab0e34";
    private static readonly string scanFolder = @"C:\Program Files\Test1";
    private static readonly string resultFile = "result.txt";
    private static readonly int MaxFileSize = 32 * 1024 * 1024; // 32MB

    static async Task Main()
    {
        await ScanFilesAsync();
    }

    private static async Task<string> UploadFileAsync(string filePath)
    {
        try
        {
            FileInfo fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > MaxFileSize)
            {
                Console.WriteLine($"Файл перевищує 32MB і не буде відправлений: {filePath}");
                return null;
            }

            Console.WriteLine($"Відправка файлу: {filePath}");

            using (HttpClient client = new HttpClient())
            using (MultipartFormDataContent form = new MultipartFormDataContent())
            {
                client.DefaultRequestHeaders.Add("x-apikey", apiKey);
                form.Add(new StreamContent(File.OpenRead(filePath)), "file", fileInfo.Name);

                HttpResponseMessage response = await client.PostAsync("https://www.virustotal.com/api/v3/files", form);
                string responseContent = await response.Content.ReadAsStringAsync();
                JsonDocument json = JsonDocument.Parse(responseContent);

                string fileId = json.RootElement.GetProperty("data").GetProperty("id").GetString();
                return fileId;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка завантаження файлу: {filePath} - {ex.Message}");
            return null;
        }
    }

    private static async Task<JsonDocument> GetAnalysisResultsAsync(string fileId)
    {
        Console.WriteLine($"Очікування аналізу (60 секунд) ID: {fileId}");
        await Task.Delay(120000); // Очікуємо 2 хвилини

        try
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("x-apikey", apiKey);
                HttpResponseMessage response = await client.GetAsync($"https://www.virustotal.com/api/v3/analyses/{fileId}");
                string responseContent = await response.Content.ReadAsStringAsync();

                return JsonDocument.Parse(responseContent);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка отримання аналізу: {fileId} - {ex.Message}");
            return null;
        }
    }

    private static async Task ScanFilesAsync()
    {
        if (!Directory.Exists(scanFolder))
        {
            Console.WriteLine($"Помилка: Папка {scanFolder} не існує.");
            return;
        }

        string[] filesToCheck = Directory.GetFiles(scanFolder);
        if (filesToCheck.Length == 0)
        {
            Console.WriteLine("У папці немає файлів для перевірки.");
            return;
        }

        StringBuilder resultText = new StringBuilder();

        foreach (string filePath in filesToCheck)
        {
            string analysisId = await UploadFileAsync(filePath);
            if (string.IsNullOrEmpty(analysisId))
            {
                Console.WriteLine($"Не вдалося завантажити файл: {filePath}");
                continue;
            }

            JsonDocument analysisData = await GetAnalysisResultsAsync(analysisId);
            if (analysisData == null)
            {
                Console.WriteLine($"Аналіз не виконано для файлу: {filePath}");
                continue;
            }

            JsonElement root = analysisData.RootElement;
            JsonElement attributes = root.GetProperty("data").GetProperty("attributes");

            string sha256 = attributes.GetProperty("sha256").GetString();
            string sha1 = attributes.GetProperty("sha1").GetString();
            string md5 = attributes.GetProperty("md5").GetString();
            long size = attributes.GetProperty("size").GetInt64();
            string fileType = attributes.GetProperty("type_description").GetString();
            string dateAnalysis = attributes.TryGetProperty("date", out JsonElement dateElement) ?
                                  DateTimeOffset.FromUnixTimeSeconds(dateElement.GetInt64()).ToString() :
                                  "Невідомо";

            JsonElement stats = attributes.GetProperty("stats");
            int totalScans = stats.GetProperty("malicious").GetInt32() +
                             stats.GetProperty("harmless").GetInt32() +
                             stats.GetProperty("undetected").GetInt32();
            int detected = stats.GetProperty("malicious").GetInt32();

            resultText.AppendLine($"\n===== Файл💻: {Path.GetFileName(filePath)} =====");
            resultText.AppendLine($"SHA-256: {sha256}");
            resultText.AppendLine($"SHA-1: {sha1}");
            resultText.AppendLine($"MD5: {md5}");
            resultText.AppendLine($"Розмір: {size} байт");
            resultText.AppendLine($"Тип: {fileType}");
            resultText.AppendLine($"Дата аналізу: {dateAnalysis}");
            resultText.AppendLine($"Статус: Завершено");
            resultText.AppendLine($"Виявлено загроз: {detected} / {totalScans}");
            resultText.AppendLine("\n===== Статистика аналізу =====");

            foreach (JsonProperty stat in stats.EnumerateObject())
            {
                resultText.AppendLine($"{stat.Name}: {stat.Value}");
            }

            resultText.AppendLine("\n===== Деталі аналізу =====");

            JsonElement results = attributes.GetProperty("results");
            foreach (JsonProperty engine in results.EnumerateObject())
            {
                JsonElement result = engine.Value;
                string category = result.TryGetProperty("category", out JsonElement categoryElement) ? categoryElement.GetString() : "Невідомо";
                string res = result.TryGetProperty("result", out JsonElement resElement) ? resElement.GetString() : "Чистий";
                string confidence = result.TryGetProperty("confidence", out JsonElement confidenceElement) ? confidenceElement.GetString() : "Невідомо";
                string method = result.TryGetProperty("method", out JsonElement methodElement) ? methodElement.GetString() : "Невідомо";

                resultText.AppendLine($"     Антивірус: {engine.Name}");
                resultText.AppendLine($"     Категорія: {category}");
                resultText.AppendLine($"     Результат: {res}");
                resultText.AppendLine($"     Довіра: {confidence}");
                resultText.AppendLine($"     Вердикт: {method}");
                resultText.AppendLine();
            }
        }

        await File.WriteAllTextAsync(resultFile, resultText.ToString());
        Console.WriteLine($"Результати збережено у {resultFile}");
    }
}
