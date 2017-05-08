using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public class SecureAES
{
    public SecureAES()
    {
        return;
    }

    Checksums CS = new Checksums();

    private string lastError = "";

    public string CreateRandomPassword(int length)
    {
        const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=_+[]{}:;@'~#,<.>/?`¬!$%^&*()";
        StringBuilder res = new StringBuilder();
        Random rnd = new Random();
        while (0 < length--)
        {
            res.Append(valid[rnd.Next(valid.Length)]);
        }
        return res.ToString();
    }

    public static byte[] GenerateRandomSalt()
    {
        byte[] data = new byte[32];

        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            for (int i = 0; i < 10; i++)
            {
                rng.GetBytes(data);
            }
        }
        return data;
    }

    public string getLastError()
    {
        return lastError;
    }

    public void AES_Encrypt(string inputFile, string password, string outputName = null)
    {
        byte[] hash = CS.getSHA1(inputFile);
        byte[] salt = GenerateRandomSalt();
        if (outputName == null)
        {
            outputName = inputFile + ".encrypted";
        }
        FileStream fsCrypt = new FileStream(outputName, FileMode.Create);

        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        RijndaelManaged AES = new RijndaelManaged();
        AES.KeySize = 256;
        AES.BlockSize = 128;
        AES.Padding = PaddingMode.PKCS7;

        var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
        AES.Key = key.GetBytes(AES.KeySize / 8);
        AES.IV = key.GetBytes(AES.BlockSize / 8);

        AES.Mode = CipherMode.CFB;

        fsCrypt.Write(hash, 0, hash.Length);
        fsCrypt.Write(salt, 0, salt.Length);

        CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

        FileStream fsIn = new FileStream(inputFile, FileMode.Open);

        byte[] buffer = new byte[1048576];
        int read;

        try
        {
            while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
            {
                Application.DoEvents();
                cs.Write(buffer, 0, read);
            }

            fsIn.Close();

        }
        catch (Exception ex)
        {
            lastError = ex.ToString();
        }
        finally
        {
            cs.Close();
            fsCrypt.Close();
            lastError = "encryptSuccess";
        }
    }

    public bool AES_Decrypt(string inputFile, string password, string outputName = null)
    {
        if (Path.GetExtension(inputFile) == ".encrypted" || !String.IsNullOrEmpty(outputName))
        {

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] hash = new byte[20];
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(hash, 0, hash.Length);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            if (outputName == null)
            {
                outputName = inputFile.Replace(".encrypted", "");
            }

            FileStream fsOut = new FileStream(outputName, FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Application.DoEvents();
                    fsOut.Write(buffer, 0, read);

                }
            }
            catch (Exception ex)
            {
                lastError = ex.ToString();
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                lastError = ex.ToString();
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }

            if (CS.convertHashToString(hash) != CS.convertHashToString(CS.getSHA1(outputName)))
            {
                File.Delete(outputName);
                lastError = "decryptIncorrectPassword";
                return false;
            }
            else
            {
                lastError = "decryptSuccess";
                return true;
            }

        }
        else
        {
            return false;
        }
    }
}