using System;

namespace Crypto
{
    public static class DiffieHellman
    {
        public static ulong CalculateSharedSecret(ulong sharedPrime, ulong sharedBase, ulong secretNumA, ulong secretNumB)
        {
            var packageToB = CryptoUtils.CalculatePowMod(sharedBase, secretNumA, sharedPrime);
            
            var packageToA = CryptoUtils.CalculatePowMod(sharedBase, secretNumB, sharedPrime);
            
            var resultA = CryptoUtils.CalculatePowMod(packageToA, secretNumA, sharedPrime);
            
            var resultB = CryptoUtils.CalculatePowMod(packageToB, secretNumB, sharedPrime);

            if (resultA != resultB)
            {
                throw new Exception("Something wen wrong when calculating the shared secret");
            }
            
            return resultA;
        }
        
        public static string ValidateSharedPrime(string stringPrime)
        {
            var numericValidationResult = ValidateNumeric(stringPrime, "Shared Prime"); 
            if (numericValidationResult != "")
            {
                return numericValidationResult;
            }

            var sharedPrime = ulong.Parse(stringPrime);

            if (!CryptoUtils.ValidatePrime(sharedPrime))
            {
                return "Number is not a prime! try again...";
            }

            return "";
        }

        public static string ValidateNumeric(string number, string numberName)
        {
            if (!ulong.TryParse(number, out _))
            {
                return $"provided value for {numberName} is not numeric! try again...";
            }

            return "";
        }

        public static string ValidateInabilityToOverflow(string stringPrime, string stringBase, string stringNumA, string stringNumB)
        {
            
            ulong.TryParse(stringPrime, out var sharedPrime);
            ulong.TryParse(stringBase, out var sharedBase);
            ulong.TryParse(stringNumA, out var secretNumA);
            ulong.TryParse(stringNumB, out var secretNumB);
            
            try
            {
                var a = checked(sharedBase * secretNumA);
                var b = checked(sharedBase * secretNumB);
                var c = checked(secretNumB * secretNumA);
                var d = checked(secretNumB * sharedPrime);
                var e = checked(secretNumA * sharedPrime);
                var f = checked(sharedBase * sharedPrime);
            }
            catch (OverflowException)
            {
                return "Ulongs can't handle numbers this big! Be more considerate!! ...try again...";
            }

            return "";
        }
    }
}