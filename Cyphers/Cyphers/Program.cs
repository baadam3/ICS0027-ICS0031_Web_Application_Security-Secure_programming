using System;
using System.Security.Cryptography;
using System.Text;

namespace Cyphers
{
    class Program
    {
        static void Main(string[] args)
        {
           while (true)
            {
                //alphabet for base64 encoding
                var base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                base64Alphabet += base64Alphabet.ToLower();
                base64Alphabet += "0123456789" + "+/=";
                //menu
                Console.WriteLine("--------------------------\nC) Caeser");
                Console.WriteLine("V) Vigenere");
                Console.WriteLine("D) Diffie-Hellman\nR) RSA");
                Console.WriteLine("E) Exit");
                Console.WriteLine("--------------------------");
                String menu = Console.ReadLine();
                menu = menu?.Trim().ToUpper();

                if (menu == "E")
                {
                    break;
                }
                else if (menu == "C")
                {
                    DoCaesar(base64Alphabet);
                }
                else if (menu == "V")
                {
                    DoVigenere(base64Alphabet);
                }
                else if (menu == "D")
                {
                    DoDiffieHellman();
                }
                else if (menu == "R")
                {
                    DoRSA();
                }
            }

        }

        static void DecodeCaesar(String base64Alphabet)
        {
            Console.WriteLine("--------------Decode-Caesar---------------");
            bool inputIsValid = false;
            int shiftAmountInt = 0;

            do
            {
                Console.WriteLine("Amount of shift:  (enter C to cancel)");
                String shiftAmountString = Console.ReadLine()?.Trim().ToUpper();

                //bail out
                if (shiftAmountString == "C")
                {
                    return;
                }

                inputIsValid = int.TryParse(shiftAmountString, out shiftAmountInt);

                if (!inputIsValid)
                {
                    Console.WriteLine($"This '{shiftAmountString}' is not a valid input");
                }

            } while (!inputIsValid);

            shiftAmountInt = shiftAmountInt % base64Alphabet.Length;

            Console.WriteLine($"Caesar shift: {shiftAmountInt}");

            Console.WriteLine("Enter encoded text:");
            //utf-8
            String base64Shifted = Console.ReadLine() ?? "";


            //Start of decoding
            shiftAmountInt *= -1;
            String base64Decoded = "";
            for (int i = 0; i < base64Shifted.Length; i++)
            {
                var b64Char = base64Shifted[i];
                var charIndex = base64Alphabet.IndexOf(b64Char);
                charIndex = charIndex + shiftAmountInt;
                if (charIndex < 0)
                {
                    charIndex = base64Alphabet.Length + charIndex;
                }
                else if (charIndex > (base64Alphabet.Length - 1))
                {
                    charIndex = charIndex - base64Alphabet.Length;
                }

                base64Decoded += base64Alphabet[charIndex];
                // Console.Write($"{b64Char} -> {base64Alphabet[charIndex]}, ");
            }

            byte[] utf8Bytes;
            try
            {
                utf8Bytes = Convert.FromBase64String(base64Decoded);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return;
            }

            Console.WriteLine("\n----------Shifted back-----------");
            Console.WriteLine($"Base64: {base64Decoded}");
            Console.WriteLine("----------Decoded---------");

            Console.WriteLine($"Original string: {Encoding.UTF8.GetString(utf8Bytes)}");
            //Console.WriteLine("-----------------------------------");
        }

        static void EncodeCaesar(String base64Alphabet)
        {
            Console.WriteLine("--------------Caesar---------------");
            bool inputIsValid = false;
            int shiftAmountInt = 0;

            do
            {
                Console.WriteLine("Amount of shift:  (enter C to cancel)");
                String shiftAmountString = Console.ReadLine()?.Trim().ToUpper();

                //bail out
                if (shiftAmountString == "C")
                {
                    return;
                }

                inputIsValid = int.TryParse(shiftAmountString, out shiftAmountInt);

                if (!inputIsValid)
                {
                    Console.WriteLine($"This '{shiftAmountString}' is not a valid input");
                }

            } while (!inputIsValid);

            shiftAmountInt = shiftAmountInt % base64Alphabet.Length;

            Console.WriteLine($"Caesar shift: {shiftAmountInt}");

            Console.WriteLine("Enter plain text:");
            //utf-8
            String plainText = Console.ReadLine() ?? "";


            var utf8 = new UTF8Encoding();
            var utf8Bytes = utf8.GetBytes(plainText);

            //base64
            var base64Str = System.Convert.ToBase64String(utf8Bytes);
            Console.WriteLine("----------Encoded----------");
            Console.WriteLine($"Base64: {base64Str}");
            String base64Shifted = "";



            //get the position of bas64 char from alphabet
            Console.WriteLine("---------Shifting-----------");
            for (int i = 0; i < base64Str.Length; i++)
            {
                var b64Char = base64Str[i];
                var charIndex = base64Alphabet.IndexOf(b64Char);
                charIndex = charIndex + shiftAmountInt;
                if (charIndex < 0)
                {
                    charIndex = base64Alphabet.Length + charIndex;
                }
                else if (charIndex > (base64Alphabet.Length - 1))
                {
                    charIndex = charIndex - base64Alphabet.Length;
                }

                base64Shifted += base64Alphabet[charIndex];
                Console.Write($"{b64Char} -> {base64Alphabet[charIndex]}, ");
            }

            Console.WriteLine($"\n{base64Shifted}");

        }

        static void DoCaesar(String base64Alphabet)
        {
            while (true)
            {
                Console.WriteLine("--------------------------\nE) Encode Caesar\nD) Decode Caesar\nC)Cancel");
                Console.WriteLine("--------------------------");
                String menu = Console.ReadLine();
                menu = menu?.Trim().ToUpper();

                if (menu == "E")
                {
                    EncodeCaesar(base64Alphabet);
                }
                else if (menu == "D")
                {
                    DecodeCaesar(base64Alphabet);
                }
                else if (menu == "C")
                {
                    return;
                }
            }
        }

        static void EncodeVigenere(String base64Alphabet)
        {
            Console.WriteLine("---------Encode-Vigenere-------------");
            bool inputIsValid = false;
            var utf8 = new UTF8Encoding();
            String key = "";
            String plainText = "";
            byte[] InputUtf8Bytes;
            byte[] KeyUtf8Bytes;
            do
            {
                Console.WriteLine("Enter plain text: (enter C: to cancel)");
                //utf-8 input
                plainText = Console.ReadLine() ?? "";
                InputUtf8Bytes = utf8.GetBytes(plainText);
                //bail out
                if (plainText == "C:" || plainText == "c:")
                {
                    return;
                }

                //utf-8 key
                Console.WriteLine("Enter key text:");
                key = Console.ReadLine() ?? "";
                if (key != "")
                {
                    inputIsValid = true;
                    int cc = 0;
                    //making sure key length > plain text length
                    for (int i = 0; i < plainText.Length + 50; i++)
                    {
                        if (key.Length <= i)
                        {
                            key += key[cc];
                            cc++;
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Invalid key\n--------------------------");
                }

                KeyUtf8Bytes = utf8.GetBytes(key);
            } while (!inputIsValid);

            //encoding
            String encodedBase64 = "";

            var b64StrKey = System.Convert.ToBase64String(KeyUtf8Bytes);
            var b64StrText = System.Convert.ToBase64String(InputUtf8Bytes);

            Console.WriteLine("------Encoding--------");
            for (int i = 0; i < b64StrText.Length; i++)
            {
                var charIndexKey = base64Alphabet.IndexOf(b64StrKey[i]);
                var charIndexText = base64Alphabet.IndexOf(b64StrText[i]);
                var charIndexEncoded = charIndexKey + charIndexText;
                if (charIndexEncoded > (base64Alphabet.Length - 1))
                {
                    charIndexEncoded = charIndexEncoded - base64Alphabet.Length;
                }

                Console.Write($"{b64StrKey[i]} + {b64StrText[i]} -> {base64Alphabet[charIndexEncoded]}, ");
                encodedBase64 += base64Alphabet[charIndexEncoded];
            }

            Console.WriteLine("\n------Base64-Key----------");
            for (int i = 0; i < b64StrKey.Length; i++)
            {
                Console.Write(b64StrKey[i]);
            }
            Console.WriteLine("\n------Base64-Encoded------\n" + encodedBase64);
        }

        static void DecodeVigenere(String base64Alphabet)
        {
            bool inputIsValid = false;
            String key;
            Console.WriteLine("Enter encoded text: (enter C: to cancel)");
            //utf-8 input
            var encodedBase64 = Console.ReadLine() ?? "";
            //bail out
            if (encodedBase64 == "C:" || encodedBase64 == "c:")
            {
                return;
            }

            do
            {
                //utf-8 key
                Console.WriteLine("Enter key text:");
                key = Console.ReadLine() ?? "";
                try
                {
                    if (key.Length < encodedBase64.Length)
                    {
                        Console.WriteLine("Invalid key\n--------------------------");
                    }
                    else
                    {
                        var temp = Convert.FromBase64String(key);
                        inputIsValid = true;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    inputIsValid = false;
                }
                
                
            } while (!inputIsValid);


            //decoding
            String decodedBase64 = "";
            Console.WriteLine("\n------Decoding--------");
            for (int i = 0; i < encodedBase64.Length; i++)
            {
                var charIndexKey = base64Alphabet.IndexOf(key[i]);
                var charIndexText = base64Alphabet.IndexOf(encodedBase64[i]);
                var charIndexEncoded = charIndexText - charIndexKey;
                if (charIndexEncoded < 0)
                {
                    charIndexEncoded = charIndexEncoded + base64Alphabet.Length;
                }

                Console.Write($"{encodedBase64[i]} - {key[i]} -> {base64Alphabet[charIndexEncoded]}, ");
                decodedBase64 += base64Alphabet[charIndexEncoded];
            }

            byte[] inputUtf8Bytes;
            try
            {
                inputUtf8Bytes = Convert.FromBase64String(decodedBase64);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return;
            }
            Console.WriteLine("\n------Base64------\n" + decodedBase64 + "\n--------Original-input------");
            Console.WriteLine($"{Encoding.UTF8.GetString(inputUtf8Bytes)}");
        }

        static void DoVigenere(String base64Alphabet)
        {
            while (true)
            {
                Console.WriteLine("--------------------------\nE) Encode Vigenere\nD) Decode Vigenere\nC)Cancel");
                Console.WriteLine("--------------------------");
                String menu = Console.ReadLine();
                menu = menu?.Trim().ToUpper();

                if (menu == "E")
                {
                    EncodeVigenere(base64Alphabet);
                }
                else if (menu == "D")
                {
                    DecodeVigenere(base64Alphabet);
                }
                else if (menu == "C")
                {
                    return;
                }
            }
        }

        static void DoDiffieHellman()
        {
            Random rnd = new Random();
            bool isBoothPrime = false;
            ulong p = 0;
            ulong g = 0;
            do
            {
                try
                {
                    //asking for numb p and validating it
                    // Math.Floor(Math.Sqrt(ulong.MaxValue)) =  4.294.967.296
                    //int.MaxValue = 2.147.483.647
                    Console.WriteLine("Enter prime number p: (enter C to cancel)");
                    String input = Console.ReadLine().Trim();
                    if (input == "C" || input == "c")//bail out
                    {
                        return;
                    }
                    p = input == "" ? GenerateRandULong() : ulong.Parse(input);
                    if (p > Math.Floor(Math.Sqrt(ulong.MaxValue)) )
                    {
                        Console.WriteLine("-------------------\nNumber is too great to use\n------------------");
                        continue;
                    }

                    if (p <= 0)
                    {
                        Console.WriteLine("-------------------\nNumber is too small to use\n------------------");
                        continue;
                    }
                    bool isPPrime = CalculateIfPrime(p);
                    
                    //asking for numb g and validating it
                    Console.WriteLine("Enter prime number g: (enter C to cancel)");
                    input = Console.ReadLine().Trim();
                    if (input == "C" || input == "c")//bail out
                    {
                        return;
                    }
                    g = input == "" ? GenerateRandULong() : ulong.Parse(input);
                    if (g > Math.Floor(Math.Sqrt(ulong.MaxValue)) )
                    {
                        Console.WriteLine("-------------------\nNumber is too great to use\n------------------");
                        continue;
                    }
                    if (g <= 0)
                    {
                        Console.WriteLine("-------------------\nNumber is too small to use\n------------------");
                        continue;
                    }
                    bool isGPrime = CalculateIfPrime(g);

                    isBoothPrime = isPPrime && isGPrime;
                    
                    if (isBoothPrime == false)
                    {
                        Console.WriteLine("-------------------\nOne or both numbers were not prime\n--------------------");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            } while (!isBoothPrime);

            int a = rnd.Next(2, 500);
            int b = rnd.Next(2, 500);
            ulong personX = CalculateSecret(g, p, (ulong)a);
            ulong personY = CalculateSecret(g, p, (ulong)b);

            ulong commonSecretForPersonX = CalculateSecret(personY, p, (ulong)a);
            ulong commonSecretForPersonY = CalculateSecret(personX, p, (ulong)b);

            Console.WriteLine($"\n---------Secret----------\nNumber of person x: {commonSecretForPersonX}\nNumber of person y: {commonSecretForPersonY}");
        }

        static void DoRSA()
        {
            while (true)
            {
                Console.WriteLine("---------------------------\nE) Encrypt RSA\nD) Decrypt RSA\nB) Bruteforce RSA\nC) Cancel\n-----------------------");
                String menu = Console.ReadLine();
                menu = menu?.Trim().ToUpper();
                if (menu == "E")
                    EncryptRSA();
                if (menu == "D")
                    DecryptRSA();
                if (menu == "B")
                    BruteForceRSA();
                if (menu == "C")
                    return;
            }
        }

        static void EncryptRSA()
        {
            Console.WriteLine("Enter message you want to encrypt: ");
            String message = Console.ReadLine().Trim();
            var utf8 = new UTF8Encoding();
            byte[] msg = utf8.GetBytes(message);
            bool isBothPrime = false;
            ulong p = 0;
            ulong q = 0;
            do
            {
                try
                {
                    Console.WriteLine("Enter a prime number p:");
                    String input = Console.ReadLine().Trim();
                    p = ulong.Parse(input);
                    bool isPrimeP = CalculateIfPrime(p);
                    if (!isPrimeP)
                    {
                        Console.WriteLine("p was not a prime\n-------------");
                        continue;
                    }

                    if (p > Math.Floor(Math.Sqrt(ulong.MaxValue)))
                    {
                        Console.WriteLine("p is too great to use\n----------");
                        continue;
                    }
                    Console.WriteLine("Enter a prime number q:");
                    input = Console.ReadLine().Trim();
                    q = ulong.Parse(input);
                    bool isPrimeQ = CalculateIfPrime(q);
                    if (!isPrimeQ)
                    {
                        Console.WriteLine("q was not a prime\n---------");
                        continue;
                    }
                    if (q > Math.Floor(Math.Sqrt(ulong.MaxValue)))
                    {
                        Console.WriteLine("q is too great to use\n----------");
                        continue;
                    }

                    if ((p - 1) * (q - 1) >= ulong.MaxValue) 
                    {
                        Console.WriteLine("(p - 1) * (q - 1) is too great, please choose smaller numbers\n----------");
                        continue;
                    }
                    isBothPrime = isPrimeP && isPrimeQ;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                
            } while (!isBothPrime);

            isBothPrime = false;
            ulong m = (p - 1) * (q - 1);
            ulong n = p * q;
            ulong E = 0;
            Console.WriteLine($"'m' = {m}, this is your private key, do not share it to anyone.");
            do
            {
                try
                {
                    Console.WriteLine("Please choose a value 'e' that is small (between 1 and 'm') and is a coprime of 'm'");
                    String input = Console.ReadLine().Trim();
                    E = ulong.Parse(input);
                    if (E < 1 || E > m)
                    {
                        Console.WriteLine("Number was not in the gives scope");
                        continue;
                    }

                    if (GCD(m,E) != 1)
                    {
                        Console.WriteLine("Chosen number was not a coprime to 'm'");
                        continue;
                    }

                    isBothPrime = true;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                
            } while (!isBothPrime);

            Console.WriteLine($"Your public keys are e = {E} and n = {n}, where e is the power and n is the mod number");
            byte[] encoded = new byte[msg.Length];
            ulong help = 0;
            for (int i = 0; i < msg.Length; i++)
            {
                help = CalculateSecret(msg[i], n, E);
                help %= 255;
              
                encoded[i] = (byte)help;
            }

           
            String cyphertxt = Convert.ToBase64String(encoded);
            Console.WriteLine($"Encoded text is: {cyphertxt}");
        }

        static void DecryptRSA()
        {
            Console.WriteLine("Enter your cypher text:");
            String cypher = Console.ReadLine().Trim();
            var utf8 = new UTF8Encoding();
            byte[] cyp = Convert.FromBase64String(cypher);
            ulong n = 0;
            ulong e = 0;
            ulong m = 0;
            bool isValid = false;
            do
            {
                try
                {
                    Console.WriteLine("Please enter your public key n:");
                    cypher = Console.ReadLine().Trim();
                    n = ulong.Parse(cypher);
                    Console.WriteLine("Please enter your public key e:");
                    cypher = Console.ReadLine().Trim();
                    e = ulong.Parse(cypher);
                    if (e > Math.Floor(Math.Sqrt(ulong.MaxValue)) || n > Math.Floor(Math.Sqrt(ulong.MaxValue)))
                    {
                        Console.WriteLine("e or n was invalid");
                        continue;
                    }

                    Console.WriteLine("Please enter your private key m:");
                    cypher = Console.ReadLine().Trim();
                    m = ulong.Parse(cypher);
                    if (m > Math.Floor(Math.Sqrt(ulong.MaxValue)))
                    {
                        Console.WriteLine("m was invalid");
                        continue;
                    }
                    isValid = true;
                }
                catch (Exception E)
                {
                    Console.WriteLine(E);
                }
            } while (!isValid);

            ulong d = 0;
            ulong k = 1;
            double temp = (1.0 + k * m) / e;
           
            do
            {
                k++;
                temp = (1.0 + k * m) / e;
            } while (temp % 1 != 0);
            
            d = (ulong)temp;
            byte[] message = new byte[cyp.Length];
            ulong help = 0;
            for (int i = 0; i < cyp.Length; i++)
            {
               
                help = CalculateSecret(cyp[i], n, d);
                help %= 255;
                message[i] = (byte)help;
            }
            String decoded = utf8.GetString(message);
            Console.WriteLine($"Decoded text is: {decoded}");
        }

        static void BruteForceRSA()
        {
            ulong pubE;
            ulong pubN;
            ulong cipher;
            ulong p = 0;
            ulong q = 0;
            ulong m;

            do
            {
                var primeOneString = GetInput("Public key n: ");

                if (!ulong.TryParse(primeOneString, out pubN))
                {
                    Console.WriteLine("not valid");
                    continue;
                }

                var primeTwoString = GetInput("Public key e: ");
                if (!ulong.TryParse(primeTwoString, out pubE))
                {
                    Console.WriteLine("not valid");
                    continue;
                }

                if (pubE == 1 || pubN == 1)
                {
                    Console.WriteLine("e or n should be more than 1");
                    continue;
                }

                var cipherString = GetInput("Cipher: ");

                if (!ulong.TryParse(cipherString , out cipher))
                {
                    Console.WriteLine("not valid");
                    continue;
                }

                break;
            } while (true);

            for (ulong i = 3; i < ulong.MaxValue; i+=2)
            {
                if ((pubN % i) == 0)
                {
                    p = i;
                    q = pubN / i;
                    break;
                }
            }

            m = (q - 1) * (p - 1);

            ulong d = 0;
            for (ulong k = 2; k < ulong.MaxValue; k++)
            {
                if ((1 + k * m) % pubE == 0)
                {
                    d = (1 + k * m) / pubE;
                    break;
                }
            }

            var plainMessage = CalculateSecret(cipher, d, pubN);
            Console.WriteLine($"plainText: {plainMessage}");
        }

        static ulong Power(ulong @base, ulong exponent)
        {
            ulong result = 1;

            for (ulong i=0; i<exponent; i++)
            {
                result *= @base;
            }

            return result;
        }

        static bool CalculateIfPrime(ulong input)
        {
            if (input == 1)
            {
                return false;
            }
            for (ulong i = 2; i < input; i++)
            {
                if (input % i == 0)
                {
                    return false;
                }
            }
            return true;
        }
        
        static ulong GenerateRandULong()
        {
            ulong randomULong;
            int saveRandom = 0;
            Random rnd = new Random();
            do
            {
                saveRandom = rnd.Next(10000000,15000000);
                randomULong = (ulong)saveRandom;
                
            } while (!CalculateIfPrime(randomULong));
            return randomULong;
        }

        static ulong CalculateSecret(ulong g, ulong p, ulong ab)
        {
            if (ab == 0)
                return 1;
            if (ab % 2 == 0)
            {
                ulong y = CalculateSecret(g, p, ab / 2);
                return (y * y) % p;
            }
            return ((g % p) * CalculateSecret(g, p, ab - 1)) % p;
        }

        static ulong GCD(ulong a, ulong b)
        {
            if (a == 0)
                return b;
            return GCD(b % a, a);
        }
        
        
        private static string GetInput(string message) {
            Console.WriteLine(message);
            Console.Write("- ");

            return Console.ReadLine()?.Trim();
        }

    }
}