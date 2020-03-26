using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace FrozenForge.DataProtection.Aes
{ 
    public class AesXmlEncryptor : IXmlEncryptor
	{
        private readonly byte[] _key;

        public AesXmlEncryptor(byte[] key)
		{
            _key = key;
		}

        public EncryptedXmlInfo Encrypt(XElement plainTextElement) 
        {
            if (plainTextElement is null)
                throw new ArgumentNullException(nameof(plainTextElement));
            
            byte[] value;

            // Create MemoryStream    
            using (var memoryStream = new MemoryStream())
            {
                plainTextElement.Save(memoryStream, SaveOptions.DisableFormatting);
                value = memoryStream.ToArray();
            }

            using var aes = new AesManaged
            {
                Key = _key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };

            byte[] encryptedValue;

            // Create encryptor    
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptedValue = encryptor.TransformFinalBlock(value, 0, value.Length);
            }

            var element = new XElement("encryptedKey",
                new XComment(" This key encrypted with MrJS's AES encryption. "),
                new XElement("value", Convert.ToBase64String(encryptedValue)));

            return new EncryptedXmlInfo(element, typeof(AesXmlDecryptor));
        }
    }
}
