# DataProtection 

## What is this?
This package features an extension method for IDataProtectionBuilder that can allow ASP.NET applications to protect keys with AES encryption and a string secret.

The default options, to use either Azure KeyVault or the file system for protecting keys, made me StackOverflow this together.

## Example usage

Here's an example where I configure an ASP.NET Core 3.1 project to persist (save) key data to a database and protect (encrypt) said data using AES encryption and a string secret:

```csharp
 services
  .AddDataProtection()
  .PersistKeysToDbContext<YourDbContextType>() 
  .ProtectKeysWithAesEncryptedSecret(dataProtectionSection.GetValue<string>("Secret")); // ← Oh boy!
   ```
