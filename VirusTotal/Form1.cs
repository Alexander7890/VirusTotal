using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace VirusTotal
{
    public partial class Form1 : Form
    {
        private const string ApiKey = "4ff03d06d0beaa010e499cd2d28bdf94da10451698b230f708895418cafe0d86";
        private const string UploadUrl = "https://www.virustotal.com/api/v3/files";
        private const string ReportUrl = "https://www.virustotal.com/api/v3/files/{0}";
        private const string ResultFilePath = "results.txt";

        private SemaphoreSlim semaphore = new SemaphoreSlim(5);

        public Form1()
        {
            InitializeComponent();
            LoadResults();
        }

        private void LoadResults()
        {
            if (File.Exists(ResultFilePath))
            {
                listBoxResults.Items.Clear();
                listBoxResults.Items.AddRange(File.ReadAllLines(ResultFilePath));
            }
        }

        private async Task ProcessFileAsync(string filePath)
        {
            await semaphore.WaitAsync();
            try
            {
                Invoke(new Action(() => listBoxResults.Items.Add($"🔄 Відправка {Path.GetFileName(filePath)}...")));

                string fileId = await UploadFileToVirusTotal(filePath);

                if (!string.IsNullOrEmpty(fileId))
                {
                    await Task.Delay(15000);
                    await GetReport(fileId, filePath);
                }
            }
            finally
            {
                semaphore.Release();
            }
        }

        private async Task<string> UploadFileToVirusTotal(string filePath)
        {
            try
            {
                var client = new RestClient(UploadUrl);
                var request = new RestRequest(Method.POST);
                request.AddHeader("x-apikey", ApiKey);
                request.AddFile("file", filePath);

                var response = await client.ExecuteAsync(request);
                JObject json = JObject.Parse(response.Content);

                return json["data"]?["id"]?.ToString();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка відправки файлу: {ex.Message}", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        private async Task GetReport(string fileId, string filePath)
        {
            try
            {
                var client = new RestClient(string.Format(ReportUrl, fileId));
                var request = new RestRequest(Method.GET);
                request.AddHeader("x-apikey", ApiKey);

                int attempts = 0;
                int maxAttempts = 6;
                JObject json = null;

                while (attempts < maxAttempts)
                {
                    var response = await client.ExecuteAsync(request);
                    json = JObject.Parse(response.Content);

                    string status = json["data"]?["attributes"]?["status"]?.ToString() ?? "pending";
                    if (status == "completed") break;

                    attempts++;
                    await Task.Delay(10000);
                }

                if (json == null)
                {
                    MessageBox.Show("Не вдалося отримати звіт.", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Отримання інформації про файл
                string sha256 = json["data"]?["attributes"]?["sha256"]?.ToString() ?? "Невідомо";
                string sha1 = json["data"]?["attributes"]?["sha1"]?.ToString() ?? "Невідомо";
                string md5 = json["data"]?["attributes"]?["md5"]?.ToString() ?? "Невідомо";
                long size = json["data"]?["attributes"]?["size"]?.Value<long>() ?? 0;
                string fileType = json["data"]?["attributes"]?["type_description"]?.ToString() ?? "Невідомо";
                string dateAnalysis = json["data"]?["attributes"]?["last_analysis_date"]?.ToString() ?? "Невідомо";

                // Статистика аналізу
                JObject analysisStats = (JObject)json["data"]?["attributes"]?["last_analysis_stats"];
                JObject engines = (JObject)json["data"]?["attributes"]?["last_analysis_results"];

                // Формуємо текстовий звіт
                StringBuilder report = new StringBuilder();
                report.AppendLine("======================================================");
                report.AppendLine($"🔎 **Аналіз файлу:** {Path.GetFileName(filePath)}");
                report.AppendLine("======================================================");
                report.AppendLine($"📌 **SHA-256:** {sha256}");
                report.AppendLine($"📌 **SHA-1:** {sha1}");
                report.AppendLine($"📌 **MD5:** {md5}");
                report.AppendLine($"📌 **Розмір файлу:** {size} байт");
                report.AppendLine($"📌 **Тип файлу:** {fileType}");
                report.AppendLine($"📌 **Дата аналізу:** {dateAnalysis}");
                report.AppendLine($"📌 **Статус аналізу:** ✅ Завершено");
                report.AppendLine($"📌 **Знайдено загроз:** ⚠️ {analysisStats["malicious"]} з {analysisStats["harmless"] + analysisStats["malicious"] + analysisStats["undetected"]}");
                report.AppendLine("------------------------------------------------------");

                // Вивід результатів антивірусного аналізу
                report.AppendLine("🛡 **Результати аналізу антивірусами**:");
                foreach (var engine in engines)
                {
                    string engineName = engine.Key;
                    string category = engine.Value["category"]?.ToString() ?? "unknown";
                    string result = engine.Value["result"]?.ToString() ?? "clean";

                    report.AppendLine($"   🔹 **{engineName}:** {category} ({result})");
                }
                report.AppendLine("======================================================");

                // Збереження результатів
                File.AppendAllText(ResultFilePath, report.ToString() + Environment.NewLine);

                // Додавання запису в інтерфейс
                Invoke(new Action(() =>
                {
                    listBoxResults.Items.Add($"✅ {Path.GetFileName(filePath)} → Аналіз завершено");
                }));

            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка отримання звіту: {ex.Message}", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog { Multiselect = true })
            {
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    List<Task> tasks = new List<Task>();

                    foreach (string filePath in openFileDialog.FileNames)
                    {
                        tasks.Add(ProcessFileAsync(filePath));
                    }

                    await Task.WhenAll(tasks);
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (File.Exists(ResultFilePath))
            {
                string results = File.ReadAllText(ResultFilePath);
                MessageBox.Show(results, "Історія перевірок", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Файл з результатами відсутній!", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
