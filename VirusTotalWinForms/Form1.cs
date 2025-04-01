using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
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


        private readonly VirusTotal virusTotal;
        private readonly SemaphoreSlim semaphore = new SemaphoreSlim(4); // Дозволяє одночасно запускати 4 файлів

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
            await semaphore.WaitAsync(); // Чекаємо на доступний слот
            try
            {
                FileInfo fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 32766 * 1024) // Перевірка на розмір файлу
                {
                    MessageBox.Show("Файл перевищує максимальний розмір (32 MB) для завантаження на VirusTotal.", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                listBoxResults.Items.Add($"🔍 Перевірка файлу: {Path.GetFileName(filePath)}...");

                // Отримуємо SHA256 файлу
                string fileHash = ComputeSHA256(filePath);

                // Швидка перевірка за хешем
                FileReport fileReport = await virusTotal.GetFileReportAsync(fileHash);

                if (fileReport.ResponseCode == FileReportResponseCode.Present)
                {
                    await ShowReportAsync(fileReport, filePath);
                    return;
                }

                // Якщо файл не знайдений, пропонувати детальну перевірку
                DialogResult result = MessageBox.Show(
                    $"Файл {Path.GetFileName(filePath)} відсутній у базі VirusTotal.\n" +
                    "Бажаєте відправити його на детальну перевірку? Це займе ~1 хвилини.",
                    "Підтвердження",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question
                );

                if (result == DialogResult.Yes)
                {
                    // Використовуємо детальну перевірку
                    await ScanFileWithEncryptionAsync(filePath);
                }
                else
                {
                    // Повторна перевірка через деякий час
                    listBoxResults.Items.Add($"⏳ Повторна перевірка через 10 сек...");
                    await Task.Delay(10000);

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
            finally
            {
                semaphore.Release(); // Звільняємо слот після завершення роботи
            }
        }

        private async Task ScanFileWithEncryptionAsync(string filePath)
        {
            listBoxResults.Items.Add($"📤 Відправка {Path.GetFileName(filePath)} на перевірку...");

            FileInfo file = new FileInfo(filePath);
            ScanResult scanResult = await virusTotal.ScanFileAsync(file);

            if (scanResult.ResponseCode == ScanFileResponseCode.Queued)
            {
                listBoxResults.Items.Add($"⏳ Очікування (~1 хв) обробки {Path.GetFileName(filePath)}...");
                await Task.Delay(60000); // 1 хвилини очікування

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

            // Чекаємо 1 секунд перед записом у файл
            await Task.Delay(1000);
            await WriteToFileAsync(ResultFilePath, report.ToString());

            listBoxResults.Items.Add($"✅ {Path.GetFileName(filePath)} → Аналіз завершено");
        }

        // Метод для безпечного запису в файл
        private async Task WriteToFileAsync(string path, string content, int retryCount = 5, int delayMs = 1000)
        {
            for (int attempt = 0; attempt < retryCount; attempt++)
            {
                try
                {
                    using (StreamWriter writer = new StreamWriter(path, true, Encoding.UTF8, 4096))
                    {
                        await writer.WriteLineAsync(content);
                    }
                    return;
                }
                catch (IOException)
                {
                    await Task.Delay(delayMs); // Чекаємо 1 секунду перед повторною спробою
                }
            }
            MessageBox.Show($"❌ Не вдалося записати результати у {path}.", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }


        private async void button1_Click_1(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog { Multiselect = true })
            {
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    await Parallel.ForEachAsync(openFileDialog.FileNames, async (filePath, _) =>
                    {
                        await ScanOrGetReportAsync(filePath);
                    });
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
