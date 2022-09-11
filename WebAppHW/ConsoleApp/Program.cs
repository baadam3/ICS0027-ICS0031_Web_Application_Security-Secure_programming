using System;
using System.Security.Cryptography;
using System.Text;
using Crypto;
using Crypto.Enums;
using RSA = Crypto.RSA;

namespace ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello Encryption");
            //Cypher(CipherTypes.Caesar);
            //Exchange();
            Encrypt();
            
        }

        public static void Cypher(CipherTypes cypherType, bool reverse = false)
        {
            var message = "";
            var key = "";

            do
            {
                message = ConsoleUtils.GetInput(reverse ? "Enter encrypted message" : "Enter message: ");
                var validationResult = CesareVigenere.ValidateMessage(message, reverse);
                if (validationResult != "")
                {
                    Console.WriteLine(validationResult);
                    continue;
                }

                break;
            } while (true);

            do
            {
                key = ConsoleUtils.GetInput(reverse ? "Enter decryption key:" : "Enter encryption key:");
                var validationResult = CesareVigenere.ValidateKey(key, message, cypherType);
                if (validationResult != "")
                {
                    Console.WriteLine(validationResult);
                    continue;
                }

                break;
            } while (true);

            var preparedMessage = CesareVigenere.PrepareMessage(message, reverse, Encoding.UTF8);
            var preparedKey = CesareVigenere.PrepareKey(key, preparedMessage, cypherType, reverse);

            var encryptedBytes = CesareVigenere.Encrypt(preparedMessage, preparedKey, cypherType, reverse);

            if (reverse)
            {
                Console.WriteLine("DECRYPTION: " + Encoding.UTF8.GetString(encryptedBytes));
            }
            else
            {
                Console.WriteLine("base64: " + Convert.ToBase64String(encryptedBytes));
            }
        }
        
        public static void Exchange()
        {
            string sharedPrimeString, sharedBaseString, secretNumAString, secretNumBString;
            
            do
            {
                sharedPrimeString = ConsoleUtils.GetInput("enter your prime...");
                var primeValidationResult = DiffieHellman.ValidateSharedPrime(sharedPrimeString);
                if (primeValidationResult != "")
                {
                    Console.WriteLine(primeValidationResult);
                    continue;
                }
            
                break;
            } while (true);

            string numericValidationResult;
            
            do
            {
                sharedBaseString = ConsoleUtils.GetInput("enter your base...");
                numericValidationResult = DiffieHellman.ValidateNumeric(sharedBaseString, "Base String");
                if (numericValidationResult != "")
                {
                    Console.WriteLine(numericValidationResult);
                    continue;
                }

                break;
            } while (true);

            do
            {
                secretNumAString = ConsoleUtils.GetInput("enter secret for person A...");
                numericValidationResult = DiffieHellman.ValidateNumeric(secretNumAString, "Secret A");
                if (numericValidationResult != "")
                {
                    Console.WriteLine(numericValidationResult);
                    continue;
                }

                break;
            } while (true);

            do
            {
                secretNumBString = ConsoleUtils.GetInput("enter secret for person B...");
                numericValidationResult = DiffieHellman.ValidateNumeric(secretNumBString, "Secret B");
                if (numericValidationResult != "")
                {
                    Console.WriteLine(numericValidationResult);
                    continue;
                }

                break;
            } while (true);

            do
            {
                var overflowValidationResult = DiffieHellman.ValidateInabilityToOverflow(sharedBaseString, sharedPrimeString, secretNumAString, secretNumBString);
                if (overflowValidationResult != "")
                {
                    Console.WriteLine(overflowValidationResult);
                    continue;
                }

                break;
            } while (true);
            
            var sharedPrime = ulong.Parse(sharedPrimeString);
            var sharedBase = ulong.Parse(sharedBaseString);
            var secretNumA = ulong.Parse(secretNumAString);
            var secretNumB = ulong.Parse(secretNumBString);

            var sharedSecret = DiffieHellman.CalculateSharedSecret(sharedPrime, sharedBase, secretNumA, secretNumB);
            
            Console.WriteLine("Shared secret it: " + sharedSecret);
        }
        
        public static void Encrypt()
        {
            
            // MESSAGE CANNOT BE HIGHER THAN N (P * Q)
            ulong p, q;
            string pString, qString;
            Console.WriteLine("RSA");

            do
            {
                pString = ConsoleUtils.GetInput("1st prime p:");
                qString = ConsoleUtils.GetInput("2nd prime q:");

                var validationResult = RSA.ValidatePrime(pString, "1st Prime");
                if (validationResult != "")
                {
                    Console.WriteLine(validationResult);
                    continue;
                }

                validationResult = RSA.ValidatePrime(qString, "2nd Prime");
                if (validationResult != "")
                {
                    Console.WriteLine(validationResult);
                    continue;
                }

                validationResult = RSA.ValidateInabilityToOverflow(pString, qString);
                if (validationResult != "")
                {
                    Console.WriteLine(validationResult);
                    continue;
                }

                break;

            } while (true);
            
            p = ulong.Parse(pString);
            q = ulong.Parse(qString);

            (ulong n, ulong m, ulong e, ulong d) keyPair = RSA.CalculateKeyPair(p, q);
            // pub key - n, e         priv key - n, d
            
            var messageStr = ConsoleUtils.GetInput("Message: ");
            
            var resultCipher = RSA.EncryptMessageRsa(messageStr, keyPair.e, keyPair.n);
            Console.WriteLine("result cipher: " + resultCipher);
            
            var resultDecryption = RSA.DecryptMessageRsa(resultCipher, keyPair.d, keyPair.n);
            Console.WriteLine("Decrypted cipher: " + resultDecryption);
        }

    }
}