using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using SecureLogin.Models;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;
using System.Threading.Tasks;

namespace SecureLogin.Controllers
{
    public class UsersController : Controller
    {
        private UserDBContext db = new UserDBContext();

        // GET: Users
        public ActionResult Index()
        {
            return View(db.Users.ToList());
        }

        // GET: Users/Details/5
        public ActionResult Details(string uname)
        {
            
            if (string.IsNullOrEmpty(uname))
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(uname);
            if (user == null)
            {
                return HttpNotFound();
            }
            
            return View(user);
        }

        // GET: Users/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateInput(true)]
        public ActionResult Create([Bind(Include = "username,email,password")] User user)
        {
            if (ModelState.IsValid)
            {
            

                var crypto = new SimpleCrypto.PBKDF2();
                user.password = crypto.Compute(user.password);
                user.salt = crypto.Salt;
                db.Users.Add(user);
                db.SaveChanges();


                return RedirectToAction("Index");
            }

            return View(user);
        }

        // GET: Users/Edit/5
        public ActionResult Edit(string uname)
        {
            if (string.IsNullOrEmpty(uname))
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(uname);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "Id,username,email,password")] User user)
        {
            if (ModelState.IsValid)
            {
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(user);
        }

        // GET: Users/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            User user = db.Users.Find(id);
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]

        public ActionResult DeleteConfirmed(int id)
        {
            User user = db.Users.Find(id);
            db.Users.Remove(user);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        
        
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }


        // POST: Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login([Bind(Include = "username,password")] User user)
        {
            if (ModelState.IsValid)
            {
                if (IsValid(user.username, user.password))
                {
                    FormsAuthentication.SetAuthCookie(user.username, false);
                    

                  
                    return RedirectToAction("Index", "Users");
                }
                else
                {
                    ModelState.AddModelError("", "Login Data is Incorrect");
                }
            }
            return View(user);
        }


        private bool IsValid(string username, string password)
        {
            var crypto = new SimpleCrypto.PBKDF2();
            bool isValid = false;

            User user = db.Users.Find(username);

            if (user != null)
            {
                if (user.password == crypto.Compute(password, user.salt))
                {
                    isValid = true;
                }
            }
            return isValid;
        }

        public ActionResult LogOut()
        {
            FormsAuthentication.SignOut();
            return View();
        }


        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }



    }

}
