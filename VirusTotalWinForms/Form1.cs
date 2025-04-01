using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using VirusTotalNet;
using VirusTotalNet.Results;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Objects;
using System.Security.Cryptography;

namespace VirusTotalWinForms
{
    public partial class Form1 : Form
    {
        private const string ApiKey = "4ff03d06d0beaa010e499cd2d28bdf94da10451698b230f708895418cafe0d86";
        private const string ResultFilePath = "results.txt";

        private VirusTotal virusTotal;

        public Form1()
        {
            InitializeComponent();
            virusTotal = new VirusTotal(ApiKey);
            virusTotal.UseTLS = true;
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

        private async Task ScanOrGetReportAsync(string filePath)
        {
            listBoxResults.Items.Add($"🔍 Перевірка файлу: {Path.GetFileName(filePath)}...");

            // Отримуємо SHA256 файлу
            string fileHash = ComputeSHA256(filePath);

            // 1. Швидка перевірка за хешем (15 сек)
            FileReport fileReport = await virusTotal.GetFileReportAsync(fileHash);

            if (fileReport.ResponseCode == FileReportResponseCode.Present)
            {
                await ShowReportAsync(fileReport, filePath);
                return;
            }

            // 2. Файл не знайдено у базі → Запитуємо користувача
            DialogResult result = MessageBox.Show(
                $"Файл {Path.GetFileName(filePath)} відсутній у базі VirusTotal.\n" +
                "Бажаєте відправити його на детальну перевірку? Це займе ~2 хвилини.",
                "Підтвердження",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question
            );

            if (result == DialogResult.Yes)
            {
                // 3. Використовуємо детальну перевірку (шифрування + 2 хв очікування)
                await ScanFileWithEncryptionAsync(filePath);
            }
            else
            {
                // 4. Повторна перевірка через 15 сек
                listBoxResults.Items.Add($"⏳ Повторна перевірка через 15 сек...");
                await Task.Delay(15000);

                fileReport = await virusTotal.GetFileReportAsync(fileHash);
                if (fileReport.ResponseCode == FileReportResponseCode.Present)
                {
                    await ShowReportAsync(fileReport, filePath);
                }
                else
                {
                    listBoxResults.Items.Add($"❌ Файл {Path.GetFileName(filePath)} не знайдено у VirusTotal. Перевірка завершена.");
                }
            }
        }


        private async Task ScanFileWithEncryptionAsync(string filePath)
        {
            listBoxResults.Items.Add($"📤 Відправка {Path.GetFileName(filePath)} на перевірку...");

            FileInfo file = new FileInfo(filePath);
            ScanResult scanResult = await virusTotal.ScanFileAsync(file);

            if (scanResult.ResponseCode == ScanFileResponseCode.Queued)
            {
                listBoxResults.Items.Add($"⏳ Очікування (~2 хв) обробки {Path.GetFileName(filePath)}...");
                await Task.Delay(120000); // 2 хвилини очікування

                // Отримання звіту
                await GetReportAsync(scanResult.Resource, filePath);
            }
            else
            {
                MessageBox.Show($"❌ Не вдалося відправити файл {file.Name}.", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async Task GetReportAsync(string resource, string filePath)
        {
            FileReport fileReport = await virusTotal.GetFileReportAsync(resource);

            if (fileReport.ResponseCode == FileReportResponseCode.Present)
            {
                await ShowReportAsync(fileReport, filePath);
            }
            else
            {
                MessageBox.Show($"Файл {Path.GetFileName(filePath)} ще не оброблений на VirusTotal.", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private async Task ShowReportAsync(FileReport fileReport, string filePath)
        {
            int positives = fileReport.Positives;
            int total = fileReport.Total;

            StringBuilder report = new StringBuilder();
            report.AppendLine("======================================================");
            report.AppendLine($"🔎 **Аналіз файлу:** {Path.GetFileName(filePath)}");
            report.AppendLine("======================================================");
            report.AppendLine($"📌 **SHA-256:** {fileReport.SHA256}");
            report.AppendLine($"📌 **SHA-1:** {fileReport.SHA1}");
            report.AppendLine($"📌 **MD5:** {fileReport.MD5}");
            report.AppendLine($"📌 **Знайдено загроз:** ⚠️ {positives} з {total}");
            report.AppendLine("------------------------------------------------------");

            foreach (KeyValuePair<string, ScanEngine> scan in fileReport.Scans)
            {
                string engine = scan.Key;
                string result = scan.Value.Result ?? "Clean";
                report.AppendLine($" 🔹 **{engine}:** {result}");
            }

            report.AppendLine("======================================================");

            File.AppendAllText(ResultFilePath, report.ToString() + Environment.NewLine);
            listBoxResults.Items.Add($"✅ {Path.GetFileName(filePath)} → Аналіз завершено");
        }

        private async void button1_Click_1(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog { Multiselect = true })
            {
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    List<Task> tasks = openFileDialog.FileNames.Select(ScanOrGetReportAsync).ToList();
                    await Task.WhenAll(tasks);
                }
            }
        }

        private void button2_Click_1(object sender, EventArgs e)
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

        private void button3_Click_1(object sender, EventArgs e)
        {
            if (listBoxResults.SelectedItem != null)
            {
                string selectedEntry = listBoxResults.SelectedItem.ToString();
                listBoxResults.Items.Remove(selectedEntry);

                var lines = File.ReadAllLines(ResultFilePath);
                File.WriteAllLines(ResultFilePath, lines.Where(line => line != selectedEntry).ToArray());

                MessageBox.Show("Запис видалено!", "Успіх", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void button4_Click_1(object sender, EventArgs e)
        {
            if (listBoxResults.SelectedItem != null)
            {
                string selectedEntry = listBoxResults.SelectedItem.ToString();
                string report = File.ReadAllText(ResultFilePath);

                if (report.Contains(selectedEntry))
                {
                    MessageBox.Show(report, "Детальна інформація", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("Детальна інформація не знайдена!", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }
        private static string ComputeSHA256(string filePath)
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

    }
}