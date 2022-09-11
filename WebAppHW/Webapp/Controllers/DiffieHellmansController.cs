using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Crypto;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Domain;
using Microsoft.AspNetCore.Authorization;
using Webapp.Data;

namespace Webapp.Controllers
{
    [Authorize]
    public class DiffieHellmansController : Controller
    {
        private readonly ApplicationDbContext _context;

        public DiffieHellmansController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: DiffieHellmans
        public async Task<IActionResult> Index()
        {
            return View(await _context.DiffieHellmans
                .Where(d => d.UserId == GetUserId())
                .ToListAsync()
            );
        }

        // GET: DiffieHellmans/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var diffieHellmanPoco = await _context.DiffieHellmans
                .FirstOrDefaultAsync(m => m.Id == id && m.UserId == GetUserId());
            if (diffieHellmanPoco == null)
            {
                return NotFound();
            }

            return View(diffieHellmanPoco);
        }

        // GET: DiffieHellmans/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: DiffieHellmans/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(DiffieHellmanPoco diffieHellmanPoco)
        {
            
            ValidateDiffieHellman(diffieHellmanPoco);

            if (ModelState.IsValid)
            {
                diffieHellmanPoco.SharedSecret = DiffieHellman.CalculateSharedSecret(diffieHellmanPoco.SharedPrime,
                    diffieHellmanPoco.SharedBase, diffieHellmanPoco.SecretA, diffieHellmanPoco.SecretB);
                diffieHellmanPoco.UserId = GetUserId();
                _context.Add(diffieHellmanPoco);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(diffieHellmanPoco);
        }

        // GET: DiffieHellmans/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var diffieHellmanPoco = await _context.DiffieHellmans
                .FirstOrDefaultAsync(m => m.Id == id && m.UserId == GetUserId());
            if (diffieHellmanPoco == null)
            {
                return NotFound();
            }
            return View(diffieHellmanPoco);
        }

        // POST: DiffieHellmans/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,SharedPrime,SharedBase,SecretA,SecretB,SharedSecret")] DiffieHellmanPoco diffieHellmanPoco)
        {
            if (id != diffieHellmanPoco.Id || diffieHellmanPoco.UserId != GetUserId())
            {
                return NotFound();
            }

            ValidateDiffieHellman(diffieHellmanPoco);
            diffieHellmanPoco.UserId = GetUserId();
            
            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(diffieHellmanPoco);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!DiffieHellmanPocoExists(diffieHellmanPoco.Id))
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
            return View(diffieHellmanPoco);
        }

        // GET: DiffieHellmans/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var diffieHellmanPoco = await _context.DiffieHellmans
                .Where(d => d.UserId == GetUserId())
                .FirstOrDefaultAsync(m => m.Id == id);
            if (diffieHellmanPoco == null)
            {
                return NotFound();
            }

            return View(diffieHellmanPoco);
        }

        // POST: DiffieHellmans/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var diffieHellmanPoco = await _context.DiffieHellmans
                .FirstOrDefaultAsync(m => m.Id == id && m.UserId == GetUserId());

            if (diffieHellmanPoco == null)
            {
                return NotFound();
            }

            _context.DiffieHellmans.Remove(diffieHellmanPoco);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        
        public string GetUserId()
        {
            var claim = User.Claims.FirstOrDefault(c =>
                c.Type == ClaimTypes.NameIdentifier);
            return claim?.Value ?? "";
        }

        private bool DiffieHellmanPocoExists(int id)
        {
            return _context.DiffieHellmans.Any(e => e.Id == id);
        }

        private void ValidateDiffieHellman(DiffieHellmanPoco diffieHellman)
        {
            var stringPrime = diffieHellman.SharedPrime.ToString();
            var stringBase = diffieHellman.SharedBase.ToString();
            var secretA = diffieHellman.SecretA.ToString();
            var secretB = diffieHellman.SecretB.ToString();
            
            var primeValidationResult = DiffieHellman.ValidateSharedPrime(stringPrime);
            if (primeValidationResult != "")
            {
                ModelState.AddModelError(nameof(DiffieHellmanPoco.SharedPrime), primeValidationResult);
            }

            var numericValidationResult = DiffieHellman.ValidateNumeric(stringBase, "Shared Base");
            if (numericValidationResult != "")
            {
                ModelState.AddModelError(nameof(DiffieHellmanPoco.SharedBase), numericValidationResult);
            }
            
            numericValidationResult = DiffieHellman.ValidateNumeric(secretA, "Secret A");
            if (numericValidationResult != "")
            {
                ModelState.AddModelError(nameof(DiffieHellmanPoco.SecretA), numericValidationResult);
            }
            
            numericValidationResult = DiffieHellman.ValidateNumeric(secretB, "Secret B");
            if (numericValidationResult != "")
            {
                ModelState.AddModelError(nameof(DiffieHellmanPoco.SecretB), numericValidationResult);
            }

            var overflowValidationResult = DiffieHellman.ValidateInabilityToOverflow(stringPrime, stringBase, secretA, secretB);
            if (numericValidationResult != "")
            {
                ModelState.AddModelError(nameof(DiffieHellmanPoco.SharedPrime), overflowValidationResult);
            }
        }
    }
}
