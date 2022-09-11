using System;
using System.Text;
using Crypto.Enums;

namespace Crypto
{
    public static class CesareVigenere
    {
        public static byte[] Encrypt(byte[] message, byte[] key, CipherTypes cipherType, bool reverse)
        {
            byte[] result = new byte[message.Length];

            if (cipherType == CipherTypes.Caesar)
            {

                for (int i = 0; i < result.Length; i++)
                {
                    var newCharValue = (message[i] + key[i]);
                    if (newCharValue > byte.MaxValue)
                    {
                        newCharValue = newCharValue - byte.MaxValue;
                    }

                    result[i] = (byte) newCharValue;
                }
            }
            else if (cipherType == CipherTypes.Vigenere)
            {
                var reverseInteger = reverse ? byte.MaxValue : 0;
                var reverseSign = reverse ? -1 : 1;

                for (int i = 0; i < message.Length; i++)
                {
                    var newCharValue = (message[i] + (key[i] * reverseSign) + reverseInteger) % byte.MaxValue;

                    result[i] = (byte) newCharValue;
                }
            }

            return result;
        }

        public static byte[] PrepareMessage(string message, bool reverse, Encoding encoding)
        {
            var result = reverse ? Convert.FromBase64String(message) : encoding.GetBytes(message);

            return result;
        }
        
        public static byte[] PrepareKey(string key, byte[] preparedMessage, CipherTypes cipherType, bool reverse)
        {
            byte[] result = new byte[preparedMessage.Length];

            switch (cipherType)
            {
                case CipherTypes.Caesar:
                    int.TryParse(key, out var keyInt);
                    keyInt = keyInt % byte.MaxValue;
                    if (reverse)
                    {
                        keyInt = byte.MaxValue - keyInt;
                    }

                    for (int i = 0; i < result.Length; i++)
                    {
                        result[i] = (byte) keyInt;
                    }
                    break;
                case CipherTypes.Vigenere:
                    for (int i = 0; i < result.Length; i++)
                    {
                        int keyValue = key[i % key.Length];

                        result[i] = (byte) keyValue;
                    }
                    
                    break;
                default:
                    throw new Exception("Something went wrong try again");
            }

            return result;
        }



        public static string ValidateKey(string key, string message, CipherTypes cipherType)
        {
            if (key.Trim() == "") return "String can not be empty! try again...";
            
            switch (cipherType)
            {
                case CipherTypes.Caesar:
                    return int.TryParse(key, out var userValue) ? "" : "the key must be a number!! try again...";
                case CipherTypes.Vigenere:
                    return key.Length > message.Length ?
                        "Please, make sure the key is shorter than the message itself! try again..." : "";
                default:
                    return "Error, please try again.";
            }
        }


        //Checks if the message is appropriately validated
        public static string ValidateMessage(string message, bool reverse)
        {
            if (reverse && !IsBase64String(message.Trim()))
            {
                return "String does not match Base64 specification! try again...";
            }

            return message.Trim() == "" ? "String can not be empty! try again..." : "";
        }
        
        private static bool IsBase64String(string base64)
        {
            Span<byte> buffer = new Span<byte>(new byte[base64.Length]);
            return Convert.TryFromBase64String(base64, buffer , out int bytesParsed);
        }

    }
}