using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ECDH
{
    class Program
    {
        static CngKey ivanKey;
        static CngKey anakey;
        static byte[] ivanPubKeyBlob;
        static byte[] anaPubKeyBlob;

        static void Main(string[] args)
        {
            KreirajKljučeve();
            byte[] kripiraniPodaci = IvanSaljePoruku("ultra tajna poruka");
            AnaPrimaPoruku(kripiraniPodaci);
            Console.Read();
        }

        private static void KreirajKljučeve()
        {
            ivanKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            anakey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            ivanPubKeyBlob = ivanKey.Export(CngKeyBlobFormat.EccPublicBlob);
            anaPubKeyBlob = anakey.Export(CngKeyBlobFormat.EccPublicBlob);
        }

        private static byte[] IvanSaljePoruku (string poruka)
        {
            Console.WriteLine("Ivan šalje poruku: {0}", poruka);
            byte[] podaci = Encoding.UTF8.GetBytes(poruka);
            byte[] krpodaci = null;

            using (var ivanAlgoritam = new ECDiffieHellmanCng(ivanKey))
            using (CngKey anaPubKey = CngKey.Import(anaPubKeyBlob, CngKeyBlobFormat.EccPublicBlob))
            {
                byte[] simKljuč = ivanAlgoritam.DeriveKeyMaterial(anaPubKey);
                Console.WriteLine("Ivan kreira simetrični ključ s Aninim javnim ključem: {0}", Convert.ToBase64String(simKljuč));

                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.Key = simKljuč;
                    aes.GenerateIV();
                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (MemoryStream ms = new MemoryStream())
                    {
                        var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

                        ms.Write(aes.IV, 0, aes.IV.Length);
                        cs.Write(podaci, 0, podaci.Length);
                        cs.Close();
                        krpodaci = ms.ToArray();
                    }
                    aes.Clear();
                }
            }

            Console.WriteLine("Ivan: Poruka je kriptirana: {0}", Convert.ToBase64String(krpodaci));
            Console.WriteLine();
            return krpodaci;
        }

        private static void AnaPrimaPoruku(byte[] kriptiraniPodaci)
        {
            Console.WriteLine("Ana prima kriptiranu poruku");
            byte[] podaci = null;

            var aes = new AesCryptoServiceProvider();
            int nBytes = aes.BlockSize >> 3;
            byte[] iv = new byte[nBytes];
            for (int i = 0; i < iv.Length; i++) iv[i] = kriptiraniPodaci[i];

            using (var anaAlgoritam = new ECDiffieHellmanCng(anakey))
            using (CngKey ivanPubKey = CngKey.Import(ivanPubKeyBlob, CngKeyBlobFormat.EccPublicBlob))
            {
                byte[] simKljuč = anaAlgoritam.DeriveKeyMaterial(ivanPubKey);
                Console.WriteLine("Ana kreira simetrični ključ s Ivanovim javnim ključem: {0}", Convert.ToBase64String(simKljuč));

                aes.Key = simKljuč;
                aes.IV = iv;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write);
                    cs.Write(kriptiraniPodaci, nBytes, kriptiraniPodaci.Length - nBytes);
                    cs.Close();
                    podaci = ms.ToArray();

                    Console.WriteLine("Ana dekriptira poruku: {0}", Encoding.UTF8.GetString(podaci));
                }
                aes.Clear();
            }
        }
    }
}
