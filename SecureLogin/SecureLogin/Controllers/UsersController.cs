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
        public ActionResult Details([Bind(Include = "Image")] UserPassChange user)
        {

            var validImageTypes = new string[]
            {
             "image/gif",
              "image/jpeg",
               "image/pjpeg",
                "image/png"
            };

    if (user.Image == null || user.Image.ContentLength == 0)
    {
        ModelState.AddModelError("ImageUpload", "This field is required");
    }
    else if (!validImageTypes.Contains(user.Image.ContentType))
    {
        ModelState.AddModelError("ImageUpload", "Please choose either a GIF, JPG or PNG image.");
    }

             WebImage photo;
            String newFileName = "";
            var imagePath = "";
            var imageThumbPath = "";

            user.username = this.User.Identity.Name;
           
                photo = new System.Web.Helpers.WebImage(user.Image.InputStream);

                if (photo != null)
                {

                    imagePath = "/Content/images/";
                    newFileName = Guid.NewGuid().ToString() + "_." + photo.ImageFormat;
                  
                   
                    photo.Save(@"~\" + imagePath + newFileName);

                    imageThumbPath = "/Content/images/thumbs/";
                    photo.Resize(width: 60, height: 60, preserveAspectRatio: true,
                       preventEnlarge: true);
                    photo.Save(@"~\" + imageThumbPath + newFileName);
                    User ruser = db.Users.Find(user.username);
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
                db.Users.Add(user);
                db.SaveChanges();


                return RedirectToAction("Index");
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
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
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

                ModelState.AddModelError("password", "Wrong Pass Nigga");
                upc.password = "";
            return View(upc);
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
