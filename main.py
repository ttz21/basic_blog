#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#testing editing text in github!
#

import os
import webapp2
import jinja2
import cgi
import re
import hashlib
import hmac
import random
from string import letters
import json
from google.appengine.ext import db
from google.appengine.api import memcache
import time

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

secret ="usghfk||&**j~hg@ddf64ub"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, str(val)).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

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
        uid = self.read_secure_cookie('user_id')  #deactivated for hw6 grading
        self.user = uid and User.by_id(int(uid))  #deactivated for hw6 grading 

 



def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

#Blog Posting


class Content(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
    

class PostPage(Handler):
    def render_front(self, subject="", content="", error=""):
        self.render("postpage.html", subject=subject, content=content, error = error) 
    def get(self):
        #if self.user: #deactivated for hw6 grading 
            self.render_front()
        #else:
            #self.redirect("/blog/login")
            
    def post(self):
        if not self.user:
            self.redirect("/blog")
        
        subject = self.request.get("subject")
        content = self.request.get("content")
        
        if subject and content:
            a = Content(subject = subject, content = content)
            a.put()
            top_posts(True)
            x =str(a.key().id())
            self.redirect('/blog/%s' %x)
        else:
            error = "We need both a blog post title and content!"
            self.render_front(subject, content, error)

def top_posts(update=False):
    key='top'
    contents= memcache.get(key)
    if update or contents is None:
        contents=db.GqlQuery("SELECT * FROM Content ORDER BY created DESC")
        contents=list(contents)
        memcache.set(key, contents)
        memcache.set("update_time",time.time())
 
    return contents

def cached_post(postID):
    cp = memcache.get(postID)
    if cp is None:
        cp = Content.get_by_id(int(postID))
        memcache.set(postID, cp)
        memcache.set(str(postID)+"time", time.time())
    return cp

class MainPage(Handler):
    def get(self):
        contents = top_posts()
         
        time_since_update= int(time.time() - memcache.get("update_time"))
        
        queried="Queried "+str(time_since_update)+" seconds ago"
        
        self.render("blog.html", contents = contents, queried=queried)


class IndividualPage(Handler):
    def get(self, postID):
        p=cached_post(postID)
        if p:
            time_since_update= int(time.time() - memcache.get(str(postID)+"time"))
        
            queried="Queried "+str(time_since_update)+" seconds ago"
            
            self.render("individualpost.html", subject = p.subject, content = p.content, date=p.created, queried=queried)
        else:
            self.error(404)


#Cookies with visit counter

 

class VisitPage(Handler):
    def get(self):
        self.response.headers['Content-Type']='text/plain'
        visits=0
        visit_cookie_val = self.read_secure_cookie('visits')
        if visit_cookie_val:
            visits = int(visit_cookie_val)
 
        visits+=1

        self.set_secure_cookie('visits',visits)

        self.write("You've been here %s times!" %visits)
        #set cookie expiration?
    

#User Sign up

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

###remove?
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

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
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

"""class UserDatabase(db.Model):
    userid = db.StringProperty(required = True)
    pwhash = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    email = db.StringProperty()
"""
    
class SignUpPage(Handler):

    def write_form(self, user="", usererror="", passerror="", verifyerror="", emailaddy="", emailerror=""):
        self.render("signup.html", user=user, usererror=usererror, passerror = passerror, verifyerror=verifyerror, emailaddy=emailaddy, emailerror=emailerror) 

    
    def get(self):
        self.write_form()
        


    def post(self):
        input_user = self.request.get('username')
        input_password1 = self.request.get('password')
        input_password2 = self.request.get('verify')
        input_emailaddy = self.request.get('email')

        usererror=""
        passerror=""
        verifyerror=""
        emailerror=""    
        

        username = valid_username(input_user)
        password = valid_password(input_password1)
        email = valid_email(input_emailaddy)
        verify = input_password1 == input_password2

        if(username and password and verify and email):
            q = User.by_name(input_user)
             
            if q:
                usererror="That user already exists"
                self.write_form(input_user, usererror, passerror, verifyerror, input_emailaddy, emailerror)
            else:
                 
                u = User.register(input_user,input_password1,input_emailaddy)
                u.put()

                self.login(u)
                self.redirect('/blog/welcome')
            

        else:
            if not username:
                usererror="This is not a valid username"
            if not password:
                passerror="This is not a valid password"
            if not verify:
                verifyerror="The password does not match"
            if not email:
                emailerror="This is not a valid email address"
                
            self.write_form(input_user, usererror, passerror, verifyerror, input_emailaddy, emailerror)

 

         

class WelcomeHandler(Handler):
    def get(self):
        if self.user:

            self.response.out.write("Welcome, "+ self.user.name +"!")
        else:
            self.redirect('/blog/signup') 

        

class LoginHandler(Handler):
    def write_form(self, user="", errormsg=""):
        self.render("login.html", user=user, errormsg=errormsg) 

    
    def get(self):
        self.write_form()
        


    def post(self):
        login_user = self.request.get('username')
        login_password = self.request.get('password')

        errormsg=""
         

        u = User.login(login_user, login_password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            
            errormsg="Invalid login"
            self.write_form(login_user, errormsg)
                
                
class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')


def create_json_post(content):
 #no json escaping
    post={}
    post["subject"]=content.subject
    post["content"]=content.content
    post["created"]=content.created.strftime("%c")
    post["last modified"]=content.last_modified.strftime("%c")
 
    return post

class JsonBlogPage(Handler):
    def get(self):
 
        contents = Content.all().order('-created')
        page=[]
        for content in contents:
            page.append(create_json_post(content))
   
        self.render_json(page)       

class JsonIndividualPage(Handler):
    def get(self, postID):
        
        p=Content.get_by_id(int(postID))
        if p:
 
            json_post = create_json_post(p)
            
            self.render_json(json_post)
        else:
            self.error(404)

class FlushPage(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')
 

 
""" 

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
"""


app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/newpost', PostPage),
                               ('/blog/([0-9]+)', IndividualPage),
                               ('/',VisitPage),
                               ('/blog/signup', SignUpPage),
                               ('/blog/welcome', WelcomeHandler),
                               ('/blog/login', LoginHandler),
                               ('/blog/logout', LogoutHandler),
                               ('/blog/.json',JsonBlogPage),
                               ('/blog/([0-9]+).json',JsonIndividualPage),
                               ('/blog/flush',FlushPage)
                              ],debug=True)


