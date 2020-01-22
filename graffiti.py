# -*- coding: windows-1251 -*-
import httplib, urllib, mimetypes
import re
from hashlib import md5
import base64
import webbrowser
import socket
from StringIO import StringIO
from Tkinter import *
import tkFileDialog
import tkMessageBox
try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

socket.setdefaulttimeout(20)

# Globals
user = None
HOST = "vkontakte.ru"

# Inner model and protocols
def make_request(method, path, data, headers, host=HOST):
    headers["Host"] = host
    headers["User-Agent"] = "Mozilla/5.0 (X11; U; Linux i686; en; rv:1.8.1.12) Gecko/20080207 Epiphany/2.20 Firefox/2.0.0.12"
    headers["Accept"] = "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
    headers["Accept-Language"] =" en-us,en;q=0.5"
#    headers["Accept-Encoding"] = "gzip, deflate"
    headers["Accept-Charset"] = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"
    headers["Keep-Alive"] = "300"
    headers["Connection"] = "keep-alive"
    try:
        conn = httplib.HTTPConnection(host, 80)
        conn.request(method, path, data, headers)
        response = conn.getresponse()
    except (IOError, socket.error), e:
        tkMessageBox.showerror(u"Ошибка", u"Не могу соединиться с сервером")
        raise
    return response

def POSTVK(path, data, headers):
    return make_request("POST", path, data, headers, "login.vk.com")
    
def POST(path, data, headers):
    return make_request("POST", path, data, headers)

def GET(path, data, headers):
    return make_request("GET", path, data, headers)

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """

    def get_content_type(filename):
        return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    
    BOUNDARY = "--OLEG-ANDREEV-PAVEL-DUROV-GRAFFITI-POST"
    L = []
    for (key, value, filename) in fields:
        L.append('--' + BOUNDARY)
        if filename:
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-type: %s' % get_content_type(filename))
        else:
            L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = "\r\n".join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def POST_multipart(selector, headers, fields, files=None):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    headers = dict(headers + [('Content-Type', content_type)])
    return POST(selector, body, headers)

def dump_response(response):
    print "ERRCODE"
    print response.status
    print "ERRMSG"
    print response.msg
    print "HEADERS"
    print response.getheaders()
    print "RESULT"
    print response.read()
    
def unicode_urlencode(params):
    d = dict()
    for k, v in params.items():
        if isinstance(v, unicode):
            d[k] = v.encode('utf-8')
        else:
            d[k] = v
    return urllib.urlencode(d)

class User(object):
    @staticmethod
    def login(email, password):
        params = unicode_urlencode({'email' : email, 'pass' : password})
        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Referer" : "Referer=http://vkontakte.ru/index.php"
        }

        response = POSTVK("http://login.vk.com/?act=login", params, headers)
        data = response.read()

        if not response.status == 200:
            return None
        id = int(re.search("l=(\d+)", str(response.msg)).groups()[0])
        s = re.search("s' value='(\w+)'", str(data)).groups()[0]
        return User(id, s, email, password)

    def __init__(self, id, s, email, pwd):
        self.id = id
        self.session = s
        self.email = email
        self.pwd = pwd

    def __repr__(self):
        return "User(%s, %s, %s)" % (self.id, self.email, self.pwd)
    
    def get_cookies(self):
        return "remixsid=%s" % self.session

#    def get_cookies(self):
#        return "remixautobookmark=30; remixchk=5; remixfriendsCommon=1; remixfriendsOnline=1; "+\
#               "remixfilters=511; remixmid=%d; remixemail=%s; remixpass=%s" % \
#               (self.id, self.email.replace('@', '%40'), md5(self.pwd).hexdigest())

    def POST_image(self, file_data, to_id, to_group=0):
        if to_group:
            to_id = 0
        query = "http://vkontakte.ru/graffiti.php?to_id=%d&group_id=%d" % (to_id, to_group)

        #file_data = file(file_name, "rb").read()
        file_hash = md5(base64.encodestring(file_data).replace('\n','')[:1024]).hexdigest()

        headers = [('Cookie', self.get_cookies()),
                   ('Referer', "http://vkontakte.ru/swf/Graffiti.swf?12")]
        fields = [('Signature', file_hash, None),
                  ('Filedata', file_data, 'graffiti.png'),
                  ('Upload', 'Submit Query', None)]

        return POST_multipart(query, headers, fields)

    def GET_friends(self):
        query = "http://vkontakte.ru/friends.php"
        response = GET(query, "", {'Cookie' : self.get_cookies()})
        if not response.status == 200:
            return None
        udata = unicode(response.read(), 'windows-1251')
        return re.findall('\[(\d+),"([^"]*)","http', udata)

# GUI part

class LoginFrame(Frame):
    def __init__(self, root):
        Frame.__init__(self, root, padx=10, pady=10)
        Label(self, text=u"Email").grid(row=0, sticky=W)
        self.email = Entry(self, width=25)
        self.email.grid(row=0, column=1, pady=5, padx=7)
        Label(self, text=u"Пароль").grid(row=1, sticky=W)
        self.password = Entry(self, show="*", width=25)
        self.password.grid(row=1, column=1, pady=5, padx=7)
        Button(self, text=u"Сайт", command=self.site_cmd).grid(row=2, sticky=W+N+E+S, padx=5)
        Button(self, text=u"Войти", command=self.login_cmd).grid(row=2, column=1, sticky=W+N+E+S, padx=5)

    def login_cmd(self):
        email = self.email.get()
        password = self.password.get()
        user = User.login(email, password)
        if not user:
            tkMessageBox.showerror(u"Ошибка", u"Неправильный логин или пароль")
        else:
            root = self.master
            self.grid_remove()
            self.destroy()

            graffiti_frame = GraffitiFrame(root, user)
            graffiti_frame.grid(row=0)
    
    def site_cmd(self):
        webbrowser.open("http://code.google.com/p/vkontakte-graffiti/", 1, 1)


class GraffitiFrame(Frame):
    def __init__(self, root, user):
        Frame.__init__(self, root, padx=10, pady=10)

        self.user = user
        self.friends = sorted([(name, id) for id, name in user.GET_friends()])
        self.friends.insert(0, (u"***Себе, любимому***", user.id))

        Label(self, text=self.user.email).grid(row=0, columnspan=2, pady=7, padx=10)
        Label(self, text=u"Файл изображения").grid(row=1, sticky=W)
        self.image_path = Entry(self)
        self.image_path.grid(row=1, column=1, pady=5, padx=7)
        Button(self,text=u"Выбрать...",command=self.select_image).grid(row=2,column=1,pady=5,padx=7)
        Label(self, text=u"ID получателя").grid(row=3, sticky=W)
        self.post_to = Entry(self)
        self.post_to.grid(row=3, column=1, pady=5, padx=7)
     
        friendsFrame = Frame(self)
        scrollbar = Scrollbar(friendsFrame, orient=VERTICAL)
        lb = self.lb = Listbox(friendsFrame, yscrollcommand=scrollbar.set)
        scrollbar.config(command=lb.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        lb.pack(side=LEFT, fill=BOTH, expand=1)
        lb.bind("<Double-Button-1>", self.select)
        friendsFrame.grid(row=4, column=0, columnspan=2, pady=5, padx=7, sticky=W+N+E+S)

        self.normalize_check = IntVar(0)
        Checkbutton(self, text=u"Выровнить",
                    variable=self.normalize_check,
                    state=(DISABLED, NORMAL)[bool(Image)]).grid(row=5, column=1, sticky=W+N+E+S)
        
        self.post = Button(self, text=u"Отправить", command=self.post_cmd)
        self.post.grid(row=6, column=1, sticky=W+N+E+S)
        self.posting = Label(self, text=u"Отправляется...")

        for name, id in self.friends:
            lb.insert(END, name)

    def select(self, param):
        sel = self.lb.curselection()
        self.post_to.delete(0, END)
        if sel:
            self.post_to.insert(END, self.friends[int(sel[0])][1])

    def select_image(self):
        formats = [
            (u"Изображения", "*.bmp *.jpg *.png"),
            (u"Все", "*.*")
        ]
        f = tkFileDialog.askopenfile(parent=self.master, filetypes=formats,
                                     mode='rb', title=u"Выберите файл с изображением")
        if f != None:
            self.image_path.delete(0, END)
            self.image_path.insert(END, f.name)
            #show_image(self.master, f.name)
        
    def post_cmd(self):
        if self.image_path.get() and self.user and self.post_to.get():
            try:
                image = file(self.image_path.get(), "rb").read()
                if self.normalize_check.get():
                    image = normalize_image(image)
            except Exception, e:
                tkMessageBox.showerror(u"Ошибка", u"Не найден файл с изображением")
                raise
            try:
                post_to = int(self.post_to.get())
            except Exception, e:
                tkMessageBox.showerror(u"Ошибка", u"Неверный ID получателя")
                raise
            responce = self.user.POST_image(image, post_to)
            if responce.status == 413:
                tkMessageBox.showerror(u"Ошибка", u"Файл слишком большой, попробуйте уменьшить разрешение в графическом редакторе")
                return
            if responce.status != 302:
                tkMessageBox.showerror(u"Ошибка", u"Неизвестная ошибка сервера")
                return
            url = "http://vkontakte.ru/graffiti.php?act=last"
            webbrowser.open(url, 1, 1)
            tkMessageBox.showinfo(u"Информация", u"Пожалуйста, перейдите в окно браузера и подтвердите отправку изображения. Если браузер не открылся, перейдите по ссылке %s" % url) 

def show_image(root, filename):
    if not Image:
        return
    top = Toplevel(root)
    img = Image.open(filename)
    tkpi = ImageTk.PhotoImage(img)
    Label(top, image=tkpi).grid(row=0)
    top.title(filename)
    root.wait_window(top)
    top.destroy()

def normalize_image(image_data):
    if not Image:
        return image_data
    img = Image.open(StringIO(image_data))
    w, h = img.size
    if w == 2*h:
        return image_data
    
    if w < 2*h:
        timg = Image.new("RGB", (2*h, h), (255, 255, 255))
        off = (2*h - w) / 2
        timg.paste(img, (off, 0, off + w, h))
    else: # w > 2*h
        timg = Image.new("RGB", (w, w / 2), (255, 255, 255))
        off = (w - 2*h) / 2
        timg.paste(img, (0, off, w, off + h))
    out = StringIO()
    timg.save(out, "jpeg")
    return out.getvalue()

def main():
    root = Tk()
    root.title(u"Граффити")
    root.resizable(False, False)
    login = LoginFrame(root)
    login.pack()
    root.update()

    root.mainloop()

if __name__ == "__main__":
    main()
