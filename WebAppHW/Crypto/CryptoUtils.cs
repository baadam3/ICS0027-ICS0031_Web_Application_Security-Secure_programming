namespace Crypto
{
    public static class CryptoUtils
    {
        public static bool ValidatePrime(ulong prime)
        {
            if (prime == 1) return true;
            
            if (prime % 2 == 0)
            {
                return false;
            }

            for (ulong i = 3; i < prime; i+=2)
            {
                if (prime % i == 0)
                {
                    return false;
                }
            }

            return true;
        }
        
        public static ulong CalculatePowMod(ulong b, ulong e, ulong m)
        {
            if (m == 1) return 0;
            ulong c = 1;
            for (ulong i = 0; i < e; i++)
            {
                c = (c * b) % m;
            }

            return c;
        }
        
        public static ulong Gcd(ulong a, ulong b)
        {
            return a == 0 ? b : Gcd(b % a, a);
        }
    }
}