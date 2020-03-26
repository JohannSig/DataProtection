using System;
using FrozenForge.DataProtection.Aes;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.DataProtection
{
    public static partial class DataProtectionBuilderExtension
    {
        public static IDataProtectionBuilder ProtectKeysWithAesEncryptedSecret(this IDataProtectionBuilder builder, string secret)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            var keyStore = new AesKeyStore(secret);

            builder.Services.AddSingleton<IKeyStore>(keyStore);
            builder.Services.Configure<KeyManagementOptions>(options => options.XmlEncryptor = new AesXmlEncryptor(keyStore.GetKey()));

            return builder;
        }
    }
}
