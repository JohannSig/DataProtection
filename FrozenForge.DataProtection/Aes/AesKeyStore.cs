using System;
using System.Security.Cryptography;
using System.Text;

namespace FrozenForge.DataProtection.Aes
{
    public interface IKeyStore
    {
        byte[] GetKey();
    }

    public class AesKeyStore : IKeyStore
    {
        private readonly byte[] _aesKey;

        public byte[] GetKey() => _aesKey;

        public AesKeyStore(string secret)
        {
            _aesKey = (new byte[16]);
            var secretBytes = Encoding.Default.GetBytes(secret);
            using var sha1M = new SHA256Managed();
            Array.Copy(sha1M.ComputeHash(secretBytes), GetKey(), 16);
        }
    }
}
