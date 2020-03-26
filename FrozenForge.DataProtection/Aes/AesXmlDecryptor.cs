using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;

namespace FrozenForge.DataProtection.Aes
{
    public class AesXmlDecryptor : IXmlDecryptor
    {
        private readonly byte[] Key;

        public AesXmlDecryptor(IServiceProvider serviceProvider)
        {
            Key = serviceProvider.GetService<IKeyStore>().GetKey(); 
        }       

        public XElement Decrypt(XElement encryptedElement)
        {
            if (encryptedElement is null)
                throw new ArgumentNullException(nameof(encryptedElement));

            var encryptedValue = Convert.FromBase64String((string)encryptedElement.Element("value"));

            byte[] decryptedValue;
            using (var aes = new AesManaged())
            {
                aes.Key = Key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                using var decryptor = aes.CreateDecryptor();
                decryptedValue = decryptor.TransformFinalBlock(encryptedValue, 0, encryptedValue.Length);
            }

            using var memoryStream = new MemoryStream(decryptedValue);
            var plainTextElement = XElement.Load(memoryStream);
            return plainTextElement;
        }
    }
}
