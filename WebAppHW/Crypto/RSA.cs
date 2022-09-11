using System;
using System.Text;

namespace Crypto
{
    public class RSA
    {
        public static (ulong n, ulong m, ulong e, ulong d) CalculateKeyPair(ulong p, ulong q)
        {
            var n = p * q;
            var m = (p - 1) * (q - 1);
            
            ulong e;
            for (e = 2; e < ulong.MaxValue; e++)
            {
                if (CryptoUtils.Gcd(e, m) == 1) break;
            }

            ulong d = 0;
            for (ulong k = 2; k < ulong.MaxValue; k++)
            {
                if ((1 + k * m) % e == 0)
                {
                    d = (1 + k * m) / e;
                    break;
                }
            }

            return (n, m, e, d);
        }

        public static string EncryptMessageRsa(string message, ulong e, ulong n)
        {
            string result = "";
            var messageBytes = Encoding.UTF8.GetBytes(message);

            int i;
            for (i = 0; i < messageBytes.Length - 1; i++)
            {
                result += CryptoUtils.CalculatePowMod(messageBytes[i], e, n) + " ";
            }

            result += CryptoUtils.CalculatePowMod(messageBytes[i], e, n);

            return result;
        }

        public static string DecryptMessageRsa(string message, ulong d, ulong n)
        {
            var splitMessage = message.Split();
            var resultBytes = new byte[splitMessage.Length];

            for (int i = 0; i < splitMessage.Length; i++)
            {
                resultBytes[i] = (byte)CryptoUtils.CalculatePowMod(ulong.Parse(splitMessage[i]), d, n);
            }

            return Encoding.UTF8.GetString(resultBytes);
        }
        
        public static string ValidatePrime(string stringPrime, string numberName)
        {
            var numericValidationResult = ValidateNumeric(stringPrime, numberName); 
            if (numericValidationResult != "")
            {
                return numericValidationResult;
            }

            if (stringPrime == "1")
            {
                return "pick a prime that is higher than 1!";
            }

            var sharedPrime = ulong.Parse(stringPrime);

            if (!CryptoUtils.ValidatePrime(sharedPrime))
            {
                return $"{numberName} is not a prime! try again...";
            }

            return "";
        }

        private static string ValidateNumeric(string number, string numberName)
        {
            if (!ulong.TryParse(number, out _))
            {
                return $"{numberName} is not numeric! try again...";
            }

            return "";
        }
        
        public static string ValidateInabilityToOverflow(string numStringA, string c)
        {
            
            ulong.TryParse(numStringA, out var numA);
            ulong.TryParse(numStringA, out var numB);
            
            try
            {
                var a = checked(numA * numB);
            }
            catch (OverflowException)
            {
                return "Ulongs can't handle numbers this big! Be more considerate!! ...try again...";
            }

            return "";
        }

        public static string ValidateProductOfPrimesInEncrypt(string message, ulong n)
        {
            var messageBytes = Encoding.UTF8.GetBytes(message);
            for (int i = 0; i < messageBytes.Length; i++)
            {
                if (messageBytes[i] > n)
                {
                    return "Product of provided primes is too small for this message, please pick bigger primes!!";
                }
            }

            return "";
        }
    }
}