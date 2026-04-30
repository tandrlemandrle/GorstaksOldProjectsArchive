using System;
using System.IO;

namespace GEdr.Engine
{
    /// <summary>
    /// Shannon entropy calculation for files and byte arrays.
    /// High entropy (>7.0) indicates packed/encrypted/compressed content.
    /// </summary>
    public static class EntropyAnalyzer
    {
        /// <summary>Calculate entropy of a file using first sampleSize bytes.</summary>
        public static double CalculateFileEntropy(string filePath, int sampleSize)
        {
            try
            {
                byte[] buffer = new byte[sampleSize];
                int read;
                using (FileStream fs = File.OpenRead(filePath))
                {
                    read = fs.Read(buffer, 0, buffer.Length);
                }
                if (read == 0) return 0;
                return CalculateEntropy(buffer, read);
            }
            catch { return 0; }
        }

        public static double CalculateFileEntropy(string filePath)
        {
            return CalculateFileEntropy(filePath, 8192);
        }

        /// <summary>Calculate Shannon entropy of a byte array.</summary>
        public static double CalculateEntropy(byte[] data, int length)
        {
            if (length == 0) return 0;

            int[] freq = new int[256];
            for (int i = 0; i < length; i++)
                freq[data[i]]++;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / length;
                entropy -= p * Math.Log(p, 2);
            }
            return Math.Round(entropy, 4);
        }

        /// <summary>Calculate entropy per PE section (if we have section offsets).</summary>
        public static double[] CalculateSectionEntropies(string filePath, PeAnalyzer.SectionInfo[] sections)
        {
            if (sections == null || sections.Length == 0) return new double[0];

            double[] result = new double[sections.Length];
            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                for (int i = 0; i < sections.Length; i++)
                {
                    int offset = (int)sections[i].RawDataOffset;
                    int size = (int)sections[i].RawDataSize;
                    if (offset < 0 || size <= 0 || offset + size > fileBytes.Length)
                    {
                        result[i] = 0;
                        continue;
                    }
                    // Calculate entropy for this section
                    int[] freq = new int[256];
                    for (int j = offset; j < offset + size; j++)
                        freq[fileBytes[j]]++;

                    double entropy = 0;
                    for (int k = 0; k < 256; k++)
                    {
                        if (freq[k] == 0) continue;
                        double p = (double)freq[k] / size;
                        entropy -= p * Math.Log(p, 2);
                    }
                    result[i] = Math.Round(entropy, 4);
                }
            }
            catch { }
            return result;
        }

        public static string EntropyVerdict(double entropy)
        {
            if (entropy >= 7.5) return "PACKED/ENCRYPTED";
            if (entropy >= 7.0) return "SUSPICIOUS";
            if (entropy >= 6.0) return "NORMAL_COMPRESSED";
            return "NORMAL";
        }
    }
}
