using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Crypto.Enums;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Domain;
using Webapp.Data;

namespace Webapp.Controllers
{
    public class CesareVigeneresController : Controller
    {
        private readonly ApplicationDbContext _context;

        public CesareVigeneresController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: CesareVigeneres
        public async Task<IActionResult> Index()
        {
            return View(await _context.CesareVigeneres.ToListAsync());
        }

        // GET: CesareVigeneres/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var cesareVigenere = await _context.CesareVigeneres
                .FirstOrDefaultAsync(m => m.Id == id);
            if (cesareVigenere == null)
            {
                return NotFound();
            }

            return View(cesareVigenere);
        }

        // GET: CesareVigeneres/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: CesareVigeneres/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CesareVigenere cesareVigenere)
        {
            ValidateCipher(cesareVigenere);

            var preparedMessage = Crypto.CesareVigenere.PrepareMessage(cesareVigenere.PlainText, false, Encoding.UTF8);
            var preparedKey = Crypto.CesareVigenere.PrepareKey(cesareVigenere.Key.ToString(), preparedMessage,
                CipherTypes.Caesar, false);

            if (ModelState.IsValid)
            {
                // maybe cover all of the cases for reversing cesare and adding vigenere
                cesareVigenere.Key = cesareVigenere.Key % byte.MaxValue; 
                //cesareVigenere.Key = int.Parse(Encoding.UTF8.GetString(preparedKey));
                cesareVigenere.CypherText = Convert.ToBase64String(Crypto.CesareVigenere.Encrypt(preparedMessage, preparedKey, CipherTypes.Caesar, false));
                
                _context.Add(cesareVigenere);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(cesareVigenere);
        }

        public void ValidateCipher(CesareVigenere cesareVigenere)
        {
            var messageValidationResult = Crypto.CesareVigenere.ValidateMessage(cesareVigenere.PlainText, false);
            
            if (messageValidationResult != "")
            {
                ModelState.AddModelError(nameof(CesareVigenere.PlainText), messageValidationResult);
            }

            var keyValidationResult =
                Crypto.CesareVigenere.ValidateKey(cesareVigenere.Key.ToString(),
                    cesareVigenere.PlainText, CipherTypes.Caesar);
            
            if (keyValidationResult != "")
            {
                ModelState.AddModelError(nameof(CesareVigenere.Key), keyValidationResult);
            }
        }
        

        // GET: CesareVigeneres/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var cesareVigenere = await _context.CesareVigeneres.FindAsync(id);
            if (cesareVigenere == null)
            {
                return NotFound();
            }
            return View(cesareVigenere);
        }

        // POST: CesareVigeneres/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Key,PlainText,CypherText")] CesareVigenere cesareVigenere)
        {
            if (id != cesareVigenere.Id)
            {
                return NotFound();
            }

            ValidateCipher(cesareVigenere);

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(cesareVigenere);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!CesareVigenereExists(cesareVigenere.Id))
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
            return View(cesareVigenere);
        }

        // GET: CesareVigeneres/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var cesareVigenere = await _context.CesareVigeneres
                .FirstOrDefaultAsync(m => m.Id == id);
            if (cesareVigenere == null)
            {
                return NotFound();
            }

            return View(cesareVigenere);
        }

        // POST: CesareVigeneres/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var cesareVigenere = await _context.CesareVigeneres.FindAsync(id);
            _context.CesareVigeneres.Remove(cesareVigenere);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool CesareVigenereExists(int id)
        {
            return _context.CesareVigeneres.Any(e => e.Id == id);
        }
    }
}
