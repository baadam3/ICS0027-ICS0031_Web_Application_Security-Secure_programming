using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Crypto;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Domain;
using Microsoft.AspNetCore.Authorization;
using Webapp.Data;

namespace Webapp.Controllers
{
    [Authorize]
    public class RsaEncryptsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public RsaEncryptsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: RsaEncrypts
        public async Task<IActionResult> Index()
        {
            return View(await _context.RsaEncrypts
                .Where(d => d.UserId == GetUserId())
                .ToListAsync());
        }

        // GET: RsaEncrypts/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var rsaEncryptPoco = await _context.RsaEncrypts
                .FirstOrDefaultAsync(m => m.Id == id && m.UserId == GetUserId());
            if (rsaEncryptPoco == null)
            {
                return NotFound();
            }

            return View(rsaEncryptPoco);
        }

        // GET: RsaEncrypts/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: RsaEncrypts/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(RsaEncryptPoco rsaEncryptPoco)
        {
            ValidateRsaInputs(rsaEncryptPoco);

            if (ModelState.IsValid)
            {
                (ulong n, ulong m, ulong e, ulong d) keyPair = RSA.CalculateKeyPair(rsaEncryptPoco.PrimeP, rsaEncryptPoco.PrimeQ);
                
                
                if (rsaEncryptPoco.Message == null)
                {
                    rsaEncryptPoco.Message = RSA.DecryptMessageRsa(rsaEncryptPoco.EncryptedMessage, keyPair.d, keyPair.n);
                }
                
                if (rsaEncryptPoco.EncryptedMessage == null)
                {
                    rsaEncryptPoco.EncryptedMessage = RSA.EncryptMessageRsa(rsaEncryptPoco.Message, keyPair.e, keyPair.n);
                }

                rsaEncryptPoco.UserId = GetUserId();
                _context.Add(rsaEncryptPoco);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(rsaEncryptPoco);
        }

        // GET: RsaEncrypts/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var rsaEncryptPoco = await _context.RsaEncrypts
                .FirstOrDefaultAsync(m => m.Id == id && m.UserId == GetUserId());
            if (rsaEncryptPoco == null)
            {
                return NotFound();
            }
            return View(rsaEncryptPoco);
        }

        // POST: RsaEncrypts/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,PrimeP,PrimeQ,Message,EncryptedMessage")] RsaEncryptPoco rsaEncryptPoco)
        {
            if (id != rsaEncryptPoco.Id || rsaEncryptPoco.UserId != GetUserId())
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(rsaEncryptPoco);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!RsaEncryptPocoExists(rsaEncryptPoco.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(rsaEncryptPoco);
        }

        // GET: RsaEncrypts/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var rsaEncryptPoco = await _context.RsaEncrypts
                .Where(d => d.UserId == GetUserId())
                .FirstOrDefaultAsync(m => m.Id == id);
            if (rsaEncryptPoco == null)
            {
                return NotFound();
            }

            return View(rsaEncryptPoco);
        }

        // POST: RsaEncrypts/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var rsaEncryptPoco = await _context.RsaEncrypts
                .FirstOrDefaultAsync(m => m.Id == id && m.UserId == GetUserId());
            
            if (rsaEncryptPoco == null)
            {
                return NotFound();
            }
            
            _context.RsaEncrypts.Remove(rsaEncryptPoco);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        
        public string GetUserId()
        {
            var claim = User.Claims.FirstOrDefault(c =>
                c.Type == ClaimTypes.NameIdentifier);
            return claim?.Value ?? "";
        }

        private bool RsaEncryptPocoExists(int id)
        {
            return _context.RsaEncrypts.Any(e => e.Id == id);
        }

        private void ValidateRsaInputs(RsaEncryptPoco rsaEncryptPoco)
        {
            var errorMessage = "Please fill out either the field for Message or EncryptedMessage not both";
            if (rsaEncryptPoco.Message != null && rsaEncryptPoco.EncryptedMessage != null)
            {
                ModelState.AddModelError(nameof(RsaEncryptPoco.Message), errorMessage);
            }

            errorMessage = RSA.ValidatePrime(rsaEncryptPoco.PrimeP.ToString(), "PrimeP");
            if (errorMessage != "")
            {
                ModelState.AddModelError(nameof(RsaEncryptPoco.PrimeP), errorMessage);
            }
            
            errorMessage = RSA.ValidatePrime(rsaEncryptPoco.PrimeQ.ToString(), "PrimeQ");
            if (errorMessage != "")
            {
                ModelState.AddModelError(nameof(RsaEncryptPoco.PrimeQ), errorMessage);
            }

            errorMessage =
                RSA.ValidateInabilityToOverflow(rsaEncryptPoco.PrimeP.ToString(), rsaEncryptPoco.PrimeQ.ToString());
            if (errorMessage != "")
            {
                ModelState.AddModelError(nameof(RsaEncryptPoco.PrimeP), errorMessage);
            }

            if (rsaEncryptPoco.Message != null)
            {
                var n = rsaEncryptPoco.PrimeP * rsaEncryptPoco.PrimeQ;
                errorMessage = RSA.ValidateProductOfPrimesInEncrypt(rsaEncryptPoco.Message, n);
            }

            if (errorMessage != "")
            {
                ModelState.AddModelError(nameof(RsaEncryptPoco.PrimeP), errorMessage);
            }
        }
    }
}
