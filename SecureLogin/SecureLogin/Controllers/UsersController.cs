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
using System.Web.Helpers;
using System.IO;
using System.Text.RegularExpressions;
using SimpleCrypto;

namespace SecureLogin.Controllers
{
    public class UsersController : Controller
    {
        private UserDBContext db = new UserDBContext();
        private LogDbContext log = new LogDbContext();
        //Controller Private Methods//

        

        // GET: Users
        public ActionResult Index()
        {
            return View(db.Users.ToList());
        }

        // GET: Users/Details/5
        public ActionResult Details()
        {
            
            if (!Request.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            User user = db.Users.Find(this.User.Identity.Name);
            if (user == null)
            {
                return HttpNotFound();
            }
            UserPassChange upc = uToUpc(user);
            
            return View(upc);
        }

        private UserPassChange uToUpc(User user){
            UserPassChange upc = new UserPassChange();
            upc.username = user.username;
            upc.avPath = user.avPath;
            upc.thumbPath = user.thumbPath;
            upc.email = user.email;

            return (upc);  
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Details([Bind(Include = "Image,email,username")] UserPassChange user)
        {
            user.username = this.User.Identity.Name;
            User ruser = db.Users.Find(user.username);
            user.avPath = ruser.avPath;
            user.thumbPath = ruser.thumbPath;
            user.email = ruser.email;
            var validImageTypes = new string[]
            {
             "image/gif",
              "image/jpeg",
               "image/pjpeg",
                "image/png"
            };

            if (user.Image == null || user.Image.ContentLength == 0)
            {

            }
            else if (user.Image.ContentLength > 1000000)
            {
                ModelState.AddModelError("ImageUpload", "Image cannot be larger than 1mb");
            }
            else if (!validImageTypes.Contains(user.Image.ContentType))
            {
                ModelState.AddModelError("ImageUpload", "Please choose either a GIF, JPG or PNG image.");

            }

            else
            {

                WebImage photo;
                String newFileName = "";
                var imagePath = "";
                var imageThumbPath = "";



                photo = new System.Web.Helpers.WebImage(user.Image.InputStream);



                imagePath = "/Content/images/";
                newFileName = Guid.NewGuid().ToString() + "_." + photo.ImageFormat;


                photo.Save(@"~\" + imagePath + newFileName);

                imageThumbPath = "/Content/images/thumbs/";
                photo.Resize(width: 100, height: 100, preserveAspectRatio: true, preventEnlarge: true);
                photo.Save(@"~\" + imageThumbPath + newFileName);

                ruser.avPath = imagePath + newFileName;
                ruser.thumbPath = imageThumbPath + newFileName;
                user.avPath = ruser.avPath;
                user.thumbPath = ruser.thumbPath;
                user.email = ruser.email;
                db.Entry(ruser).State = EntityState.Modified;
                db.SaveChanges();

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

                string actKey = "/Activ?kstr=" + RandomPassword.Generate(44, PasswordGroup.Uppercase, PasswordGroup.Lowercase, PasswordGroup.Numeric);
                user.actString = actKey;

                db.Users.Add(user);
                db.SaveChanges();


                return RedirectToAction("Login");
            }

            return View(user);
        }

        // GET: Users/Edit/5
        public ActionResult Edit()
        {
            
            if (!Request.IsAuthenticated)
            {   
               return RedirectToAction("Login");
            }
            string name = this.User.Identity.Name;

            User user = db.Users.Find(name);
            UserPassChange upc = new UserPassChange();
            upc.email = user.email;
            upc.username = user.username;
            
            user.password = "";
           
            return View(upc);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateInput(true)]
        public ActionResult Edit([Bind(Include = "email,password,newpass,confpass")] UserPassChange upc)
        {
            
                var crypto = new SimpleCrypto.PBKDF2();
                
                upc.username = this.User.Identity.Name;
                User user = db.Users.Find(upc.username);
                upc.password = crypto.Compute(upc.password,user.salt);
                if (upc.password == user.password) {
                    user.password = crypto.Compute(upc.newpass);
                    user.salt = crypto.Salt;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                    return RedirectToAction("Index");
                }

                ModelState.AddModelError("password", "Wrong Password");
                upc.password = "";
            return View(upc);
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
                    user = db.Users.Find(user.username);
                    FormsAuthentication.SetAuthCookie(user.username, false);
                    user.attempts = 0;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                    return RedirectToAction("Details", "Users");
                }
                user = db.Users.Find(user.username);
                if (user.locked == true) { 
                    ModelState.AddModelError("LoginMsg", "This Account is locked, follow link in email to unlock"); 
                }
                else
                {
                    user.attempts++;   
                    ModelState.AddModelError("LoginMsg", "Login Data is Incorrect. "+ (5-user.attempts)+ " Attempts remaining");      
                    if (user.attempts == 5)
                    {
                        user.locked = true;
                        string unlKey = "/Unlock?kstr=" + RandomPassword.Generate(44, PasswordGroup.Uppercase, PasswordGroup.Lowercase, PasswordGroup.Numeric);
                        
                        user.unlString = unlKey;
                        db.Entry(user).State = EntityState.Modified;
                        db.SaveChanges();
                    }
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                }
            }
            return View(user);
        }

        public ActionResult Reset(string kstr)
        {
            if (kstr != null && kstr.Length > 0 && kstr.Length < 45)
            {
                kstr = Regex.Replace(kstr, "[^0-9a-zA-Z]+", "");
                User user = db.Users.FirstOrDefault(User => User.forString == "/Unlock?kstr="+kstr);

                UserPassChange upc = uToUpc(user);
                if (user != null)
                {

                    return View(upc);
                }
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Reset([Bind(Include = "username,newpass,confpass")] UserPassChange upc)
        {

            var crypto = new SimpleCrypto.PBKDF2();
            
            //username = ViewBag.username;
            //upc.username = this.User.Identity.Name;
            User user = db.Users.Find(upc.username) ;
            upc.password = crypto.Compute(upc.newpass);
            user.password = upc.password;
            user.forString = "";
                user.salt = crypto.Salt;
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                ModelState.AddModelError("LoginMsg", "Password Successfuly Changed!");
                return RedirectToAction("Login");
        }
        public ActionResult Unlock(string kstr)
        {
            if (kstr != null && kstr.Length > 0 && kstr.Length < 45)
            {
                kstr = Regex.Replace(kstr, "[^0-9a-zA-Z]+", "");
                User user = db.Users.FirstOrDefault(User => User.unlString == "/Unlock?kstr="+kstr);
               
                UserPassChange upc = uToUpc(user);
                if (user != null)
                {
                    user.locked = false;
                    user.attempts = 0;
                    user.unlString = null;
                    db.Entry(user).State = EntityState.Modified;
                    db.SaveChanges();
                    return RedirectToAction("Login", "Users", new { LoginMsg = "Unlock Successful" });
                }
            }
            return RedirectToAction("Index");
        }

        public ActionResult Forgot()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Forgot([Bind(Include = "username,email")] UserPassChange upc)
        {

            User user = db.Users.Find(upc.username);
            if (user.email != upc.email) 
            { 
                user = null; 
            }
            
            if (user != null)
            {
                String forKey = "/Reset?kstr=" + RandomPassword.Generate(44, PasswordGroup.Uppercase, PasswordGroup.Lowercase, PasswordGroup.Numeric);
                user.forString = forKey;
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();
                  return RedirectToAction("Index", "Users");
             }
             else
                {
                    ModelState.AddModelError("Error", "User or Email not found");
                }

            return View(upc);
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



        public ActionResult SignOut()
        {
            FormsAuthentication.SignOut();

            return RedirectToAction("LogOut");
        }

        public ActionResult LogOut()
        {


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
