using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using KernelSpyScanner.Models;

namespace KernelSpyScanner.Reporting
{
    public static class JsonReport
    {
        public static bool Export(string path, IEnumerable<Finding> findings)
        {
            try
            {
                var list = new List<Finding>(findings);
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var payload = new
                {
                    tool = "KernelSpy Scanner",
                    version = "1.4.4",
                    generated = DateTime.Now,
                    totalFindings = list.Count,
                    findings = list
                };
                string json = JsonSerializer.Serialize(payload, options);
                File.WriteAllText(path, json, Encoding.UTF8);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
