using System.Security.Cryptography;
using System.Security.Permissions;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Runtime.ConstrainedExecution;
using CsvHelper;
using CsvHelper.Configuration;
using System.Globalization;

namespace ParseCER
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Незадан путь к сертификатам");
                return;
            }
            Console.Write("Получаем файлы сертификатов...");
            List<CerInfo> cer_list = new List<CerInfo>();
            string[] files = Directory.GetFiles(args[0], "*.cer", SearchOption.AllDirectories);
            Console.WriteLine($"{files.Length} получено");
            foreach (var item in files)
            {
                X509Certificate2? cer = GetCER(item);
                if (cer != null)
                {
                    CerInfo cer_info = new CerInfo();
                    //Console.WriteLine("{0}Subject: {1}{0}", Environment.NewLine, cer.Subject);
                    string[] tags = cer.Subject.Split(", ");
                    StringBuilder sb = new StringBuilder();
                    foreach (string tag in tags)
                    {
                        if (tag.StartsWith("SN="))
                        {
                            //Console.Write(tag.Replace("SN=", string.Empty));
                            sb.Append(tag.Replace("SN=", string.Empty));
                            sb.Append(' ');
                        }
                        if (tag.StartsWith("G="))
                        {
                            //Console.Write($"{tag.Replace("G=", string.Empty)}");
                            sb.Append(tag.Replace("G=", string.Empty));
                            //sb.Append(';');
                        }

                    }
                    cer_info.Name = sb.ToString();
                    cer_info.DataWT = cer.NotAfter.Date;
                    sb.Append(DateOnly.FromDateTime(cer.NotAfter.Date).ToString());
                    sb.Append(';');
                    foreach (string tag in tags)
                    {
                        if (tag.StartsWith("T="))
                        {
                            //Console.WriteLine(tag.Replace("T=", string.Empty));
                            sb.Append(tag.Replace("T=", string.Empty));
                            cer_info.JobTitle = tag.Replace("T=", string.Empty);
                        }
                    }
                    cer_list.Add(cer_info);

                    //Console.WriteLine(sb.ToString());
                    //Console.WriteLine(cer.Subject);
                }
            }
            PrintTable(cer_list);
            WriteCSV(cer_list, "./cer.csv");
            Console.WriteLine("Таблицаа сохранена в ./cer.csv");
        }
        static X509Certificate2? GetCER(string fileName)
        {
            X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(fileName);
            return cert;
        }
        static void PrintTable(List<CerInfo> CerList)
        {
            const int fio_len = -40;
            const int job_len = -60;
            const int data_len = -14;
            const int days_len = -13;
            const int row_len = 140;
            Console.WriteLine(new string('-', row_len)); // Разделительная линия
            // Заголовки столбцов с указанием ширины (положительное число — выравнивание по правому краю, отрицательное — по левому)
            Console.WriteLine($"| {"ФИО",fio_len} | {"Должность",job_len} | {"Дата окончания",data_len} | {"Дней осталось",days_len} |");
            Console.WriteLine(new string('-', row_len));

            // Данные строки таблицы
            //Console.WriteLine($"{1,-5} | {"Алексей",-12} | {28,7} | {"Москва",-10}");
            //Console.WriteLine($"{2,-5} | {"Мария",-12} | {24,7} | {"Казань",-10}");
            //Console.WriteLine($"{3,-5} | {"Иван",-12} | {32,7} | {"Сочи",-10}");
            foreach (CerInfo cer in CerList)
            {
                Console.WriteLine($"| {cer.Name,fio_len} | {cer.JobTitle,job_len} | {cer.Data,data_len} | {(cer.DataWT - DateTime.Now).Days,days_len} |");
            }
            Console.WriteLine(new string('-', row_len));
        }
        static void WriteCSV(List<CerInfo> CerList, string FilePath)
        {
            var config = new CsvConfiguration(System.Globalization.CultureInfo.CurrentCulture);
            config.Delimiter = ";";
            //config.HasHeaderRecord = false;
            using (var writer = new StreamWriter(FilePath))
            using (var csv = new CsvWriter(writer, config))
            {
                csv.Context.RegisterClassMap<CerInfoMap>();
                csv.WriteRecords(CerList);
            }
        }
    }
    public class CerInfo
    {
        public string? Name { get; set; }
        public string? JobTitle { get; set; }
        public DateOnly Data
        {
            get
            {
                return DateOnly.FromDateTime(DataWT);
            }
        }
        public DateTime DataWT { get; set; }
    }
    public class CerInfoMap : ClassMap<CerInfo>
    {
        public CerInfoMap()
        {
            // Автоматически маппим все свойства
            AutoMap(System.Globalization.CultureInfo.InvariantCulture);
            // И явно указываем, какое свойство нужно игнорировать
            Map(m => m.DataWT).Ignore();
        }
    }
}
