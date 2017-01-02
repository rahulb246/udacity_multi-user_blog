import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# SECRET KEY
secret = 'secret'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Basic handler for blog. Handles basic and frequently used functions
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# Helper functions for User model functions
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# Class that handles User database model
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    # User model functions
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(), name = name, pw_hash = pw_hash, email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Class that handles creation of post database model
class Post(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.StringProperty(required = True)
    likes = db.StringListProperty()
    parent_post = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

# Class that handles displaying all posts in the front page
class FrontPage(Handler):
    def get(self):
        posts = Post.all().filter('parent_post =', None).order('-created')
        uid = self.read_secure_cookie('user_id')

        self.render('front.html', posts = posts, uid=uid)

# Class that handles individual details of the post
# post id in the url is used as reference
class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        uid = self.read_secure_cookie('user_id')

        if post.likes and uid in post.likes:
            likeText = 'unlike'
        else:
            likeText = 'like'

        totalLikes = len(post.likes)
        comments = Post.all().filter('parent_post =', post_id)

        for comment in comments:
            print(comments)

        if not post:
            self.error(404)
            return

        post._render_text = post.content.replace('\n', '<br>')
        self.render(
                    "post.html",
                    post = post,
                    likeText = likeText,
                    totalLikes = totalLikes,
                    uid = uid,
                    comments = comments)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        title = self.request.get('title')
        content = self.request.get('content')
        uid = self.read_secure_cookie('user_id')

        if title and content:
            post = Post(parent = blog_key(), title = title, content = content, user_id = uid, parent_post = post_id)
            post.put()
            self.redirect('/post/%s' % post_id)
        else:
            err_msg = "title and content, please!"
            self.render("post.html", title=title, content=content, error=err_msg)

# Class that handles likes of the post
# post id in the url is used as reference
# doesnt allow users liking their own posts
class LikePage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        uid = self.read_secure_cookie('user_id')
        if not uid:
            self.render("login.html")
            return
        if not post:
            self.error(404)
            return

        if post.user_id != uid:

            if post.likes and uid in post.likes:
                post.likes.remove(uid)
            else:
                post.likes.append(uid)

            post.put()
            print(post.likes)

            self.redirect('/post/%s' % str(post.key().id()))

        else:
            err_msg = 'Owner\'s can\'t like or unlike their own posts'
            self.render("error.html", error = err_msg, uid = uid)

# CLass that handles deleting of a post
# post id in the url is used as reference
# Allows if the user is the owner of the post
# displys warning for other users
class DeletePage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.redirect("/")
            return

        uid = self.read_secure_cookie('user_id')
        if not uid:
            self.render("login.html")
            return

        if post.user_id != uid:
            err_msg = 'Only owner of this post can delete this post'
            self.render("delete.html", error = err_msg, uid=uid)
        else:
            err_msg = ''
            db.delete(key)
            self.render("delete.html", error = err_msg, uid=uid)

# Class that handles editing of a post.
# post id in the url is used as reference
# Allows editing if the user is the owner of the post
# displays warning for other users
class EditPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        uid = self.read_secure_cookie('user_id')
        if not uid:
            self.render("login.html")
            return

        if post.user_id != uid:
            err_msg = 'only owner of this post can edit this !!'
            self.render("edit.html", post = post, error = err_msg, uid=uid)
        else:
            err_msg = ''
            self.render("edit.html", post = post, error = err_msg, uid=uid)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        uid = self.read_secure_cookie('user_id')

        title = self.request.get('title')
        content = self.request.get('content')

        if title and content and post.user_id == uid:
            post.title = title
            post.content = content
            post.put()
            if post.parent_post:
                redirect_id = post.parent_post
            else:
                redirect_id = post.key().id()
            self.redirect('/post/%s' % str(redirect_id))
        else:
            err_msg = "Please fill in the valid subject and content !!"
            self.render("edit.html", post = post, error=err_msg, uid = uid)

# Class that handles creation of a new post only if the user is signed in
class NewPost(Handler):

    # function that verify if the user is signed in or not
    def get(self):
        uid = self.read_secure_cookie('user_id')
        if self.user:
            self.render("newpost.html",  uid=uid)
        else:
            self.redirect("/login")

    # function that handles creation of new post
    def post(self):
        if not self.user:
            return self.redirect('/login')

        title = self.request.get('title')
        content = self.request.get('content')

        uid = self.read_secure_cookie('user_id')

        if title and content:
            post = Post(parent = blog_key(), title = title, content = content, user_id = uid)
            post.put()
            self.redirect('/post/%s' % str(post.key().id()))
        else:
            err_msg = "title and content, please!"
            self.render("newpost.html", title=title, content=content, error=err_msg)

# Class to handle Logging out the user from the blog session
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

# Class to handle login of users into the blog
class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/')
        else:
            err_msg = 'Sorry Invalid login, PLease try again !!'
            self.render('login.html', error = err_msg)

# Class that handles the signup page, shows error if the fields do not match the validation's above.
class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)
        # Validation for username
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        def valid_username(username):
            return username and USER_RE.match(username)

        # Validation for password
        PASS_RE = re.compile(r"^.{3,20}$")
        def valid_password(password):
            return password and PASS_RE.match(password)

        # Validation for email
        EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        def valid_email(email):
            return not email or EMAIL_RE.match(email)

        if not valid_username(self.username):
            params['error_username'] = "Sorry, Not a valid username, PLease try again !!"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Sorry, Not a valid password, Please try agian !!"
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Oops !! passwords didn't match, Please try again !!"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Sorry, Not a valid email, Please try again !!"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# Class to create new user for the blog
class Register(Signup):
    def done(self):
        # making sure the user is not registered earlier
        user = User.by_name(self.username)
        if user:
            err_msg = 'The user already exists.'
            self.render('signup.html', error_username = err_msg)
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/')

# Welcome page after a user succesfully logs in
class Welcome(Handler):
    def get(self):
        if self.user:
            uid = self.read_secure_cookie('user_id')
            self.render('welcome.html', username = self.user.name, uid=uid)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/?', FrontPage),
                               ('/post/([0-9]+)', PostPage),
                               ('/delete/([0-9]+)', DeletePage),
                               ('/edit/([0-9]+)', EditPage),
                               ('/like/([0-9]+)', LikePage),
                               ('/newpost', NewPost),
                               ('/logout', Logout),
                               ('/login', Login),
                               ('/signup', Register),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
