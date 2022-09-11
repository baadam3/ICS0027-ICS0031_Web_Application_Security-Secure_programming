using Microsoft.AspNetCore.Identity;

namespace Domain
{
    public class RsaEncryptPoco
    {
        public int Id { get; set; }

        public ulong PrimeP { get; set; }
        
        public ulong PrimeQ { get; set; }

        public string Message { get; set; }
        
        public string EncryptedMessage { get; set; }
        
        public string UserId { get; set; }
        public IdentityUser User { get; set; }
    }
}