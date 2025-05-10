import requests, base64, hashlib, subprocess
from pprint import pprint
import time, json, sys, os, traceback, zlib
from datetime import datetime
from zoneinfo import ZoneInfo
from time import sleep
from pprint import pprint, pformat
from base64 import b64encode
sess=requests.session()
sess.headers.update({"User-Agent":"git-lfs/3.0.2 (GitHub; linux amd64; go 1.17.2)"})

def _getauthheader(sshtarget, sshkey, repo, action="upload", sshuser="git", sshport=22):
    cmdline = ["ssh", "-o","StrictHostKeyChecking=no", f"{sshuser}@{sshtarget}", "-p", f"{sshport}", "-i", sshkey, "git-lfs-authenticate", repo, action]
    if os.getenv("DEBUG", False):
        print("[STEP1] SSH Get LFS Token:")
        print("# "+" ".join(cmdline))
    x = subprocess.check_output(cmdline)
    if os.getenv("DEBUG", False):
        try:
            print("response:")
            pprint(json.loads(x), width=40)
            print()
        except:
            print("lfs token response:",x)
    d = json.loads(x)
    if "expires_in" in d:
        expires_in = d["expires_in"]
    elif "expires_at" in d:
        expirets = datetime.strptime(d["expires_at"].split(".")[0].split("+")[0], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=ZoneInfo("Asia/Shanghai")).timestamp()
        expires_in = expirets - time.time()
        print("expires in:", expires_in)
    else:
        print("[warning] no expire info in lfs token")
        expires_in = 3600
    authheader = d["header"]
    return authheader, expires_in

def debugprint(x, raw=False):
    if not os.getenv("DEBUG",False):
        return
    print(x.request.method, x.url)
    for k,v in x.request.headers.items():
        print(f"{k}: {v}")
    print("\n"+(x.request.body.decode() if x.request.body else ''))
    
    print("\nresponse:", x)
    for k,v in x.headers.items():
        print(f"{k}: {v}")
    print()
    if raw or x.headers.get("content-type", None)=="application/octet-stream":
        print(x.content[:100], ("data truncated" if len(x.content)>100 else ""))
    else:
        try:
            pprint(x.json(), width=80)
        except:
            print(x.text[:100], ("data truncated" if len(x.text)>100 else ""))
    print()

DEFAULT_HEADER = {
    "Accept": "application/vnd.git-lfs+json", 
    "Content-Type": "application/vnd.git-lfs+json",
}

class GIT_LFS():
    def __init__(self, sshtarget, sshkey, repo, sshuser="git", sshport=22, lfsurl=None, usehttp=False, overrideauth=None):
        self.sshtarget = sshtarget
        self.sshkey = sshkey
        if not repo.endswith(".git"):
            repo = repo+".git"
        self.repo = repo
        self.sshuser = sshuser
        self.sshport = sshport
        if not lfsurl:
            lfsurl = f"https://{sshtarget}/{repo}/info/lfs/objects/batch"
        if usehttp:
            lfsurl = lfsurl.replace("https://", "http://")
        self.lfsurl = lfsurl
        self.cachefile = "__pycache__/"+f"{sshtarget}_{repo}_{sshkey}.json".replace("/","_")
        try:
            self.expiretime,self.authheader = json.load(open(self.cachefile, "r"))
        except:
            self.expiretime,self.authheader = {}, {}
        if sshkey is None or overrideauth: #anonymous HTTP or overrideauth=user:password
            self.expiretime = {"download":time.time()+86400*365, "upload":time.time()+86400*365}
            h = {"Authorization":""}
            if overrideauth:
                h["Authorization"] = "Basic "+b64encode(overrideauth.encode("utf-8")).decode()
            self.authheader = {"download":h, "upload":h}
    
    def getauthheader(self, action):
        if time.time()>self.expiretime.get(action,0)-10:
            self.authheader[action], expires_in = _getauthheader(self.sshtarget, self.sshkey, self.repo, action, self.sshuser, self.sshport)
            self.expiretime[action] = time.time()+expires_in
            open(self.cachefile, "w").write(json.dumps([self.expiretime,self.authheader]))
        h = DEFAULT_HEADER.copy()
        h.update(self.authheader[action])
        return h
    
    def get_upload_url(self, sha256, size, action="upload"):
        print("[get_upload_url]", sha256, size)
        x = sess.post(self.lfsurl, json={"operation":"upload", "objects":[{"oid":sha256, "size":size}], "ref":{ "name": "refs/heads/master"},"hash_algo":"sha256","transfers":["basic"]}, headers=self.getauthheader(action))
        debugprint(x)
        d = x.json()["objects"][0]
        return d["actions"]
    
    def get_download_url(self, sha256, size, action="download"):
        print("[get_download_url]", sha256, size)
        x = sess.post(self.lfsurl, json={"operation":"download", "objects":[{"oid":sha256, "size":size}], "ref":{ "name": "refs/heads/master"},"hash_algo":"sha256","transfers":["basic"]}, headers=self.getauthheader(action))
        debugprint(x)
        d = x.json()["objects"][0]
        return d
        #return d["actions"]["upload"]["href"], d["actions"]["upload"]["header"]
    
    def do_verify_step(self, sha256, size, action):
        h = DEFAULT_HEADER.copy()
        ah = action.get("header", {})
        if "Authorization" not in ah:
            ah = self.getauthheader("upload")
        h.update(ah)
        url = action["href"]
        print("[verify POST]", url)
        x = sess.post(url, json={"oid":sha256, "size":size}, headers=h)
        debugprint(x)
        assert x.status_code == 200, "verify call failure"

def file_put(url, content, headers):
    h = {"Content-Type":"application/octet-stream"}
    h.update(headers)
    if "Transfer-Encoding" in h:
        del h["Transfer-Encoding"]
    if "Authorization" in h:
        h["Authorization"] = h["Authorization"].strip()
        if "X-Amz-Signature" in url:
            del h["Authorization"]
    print("[STEP3] file_upload PUT", url, "\nheaders:", h)
    x = sess.put(url, data=content, headers=h)
    if os.getenv("DEBUG", False):
        print("response:", x.text, x)
    assert x.status_code in [200,201], "file put failure"

class RunTest():
    def __init__(self, sshtarget, repo, keysfolder="./keys", verifydownload=False, overrideurl=None, put_force_header=None, download_force_header=None, **kwargs):
        self.sshtarget = sshtarget
        self.repo = repo
        self.key_readwrite = keysfolder+"/readwrite"
        assert os.path.isfile(self.key_readwrite), "readwrite key missing"
        self.key_deployread = keysfolder+"/deployread"
        assert os.path.isfile(self.key_deployread), "deployread key missing"
        self.key_otheruser = keysfolder+"/otheruser"
        assert os.path.isfile(self.key_otheruser), "otheruser key missing"
        self.key_anonymous = keysfolder+"/anonymous"
        assert os.path.isfile(self.key_anonymous), "anonymous key missing"
        self.kwargs = kwargs
        self.verifydownload = verifydownload
        self.overrideurl = overrideurl or {"upload":None, "download":None}
        self.put_force_header = put_force_header or {}
        self.download_force_header = download_force_header or {}
        if kwargs.get("overrideauth", False):
            self.key_readwrite = None
    
    def test1_anonymous_ssh(self):
        x = GIT_LFS(self.sshtarget, self.key_anonymous, self.repo, **self.kwargs)
        try:
            token = x.getauthheader(action="download")
            print("[VULN] anonymous get token:", token)
        except:
            traceback.print_exc()
            print("[TEST OK] test_anonymous_ssh failed")
    
    def test2_upload_process(self, key="readwrite", action="upload", doverify=True):
        x = GIT_LFS(self.sshtarget, {"readwrite":self.key_readwrite, "deployread":self.key_deployread, "otheruser":self.key_otheruser, "anonymous":None}[key], self.repo, **self.kwargs)
        h = x.getauthheader(action)
        size = 1024*1024 #1MB
        randomdata = os.urandom(size)
        sha256 = hashlib.sha256(randomdata).hexdigest()
        print("sha256:", sha256)
        if self.overrideurl["upload"]:
            url = self.overrideurl["upload"].format(sshtarget=self.sshtarget, repo=self.repo, sha256=sha256, size=size)
            actions = {}
            del h["Content-Type"]
        else:
            actions = x.get_upload_url(sha256, size, action)
            url = actions["upload"]["href"]
            h.update(actions["upload"].get("header",{}))
        h.update(self.put_force_header)
        file_put(url, randomdata, h)
        if doverify and "verify" in actions:
            x.do_verify_step(sha256, size, actions["verify"])
        print("upload ok:", sha256)
        return sha256
    
    def overwrite_existing_file(self, sha256, newcontent, url=None, headers=None, key="readwrite"):
        x = GIT_LFS(self.sshtarget, {"readwrite":self.key_readwrite, "deployread":self.key_deployread, "otheruser":self.key_otheruser, "anonymous":None}[key], self.repo, **self.kwargs)
        h = x.getauthheader("upload")
        del h["Content-Type"]
        if headers:
            h.update(headers)
        if url is None:
            actions = x.get_upload_url(sha256, 1, "upload")
            url = actions["upload"]["href"]
            h = actions["upload"].get("header",{})
        file_put(url, newcontent, h)
    
    def test3_download_process(self, sha256, key="readwrite", size=1024*1024, action="download"):
        x = GIT_LFS(self.sshtarget, {"readwrite":self.key_readwrite, "deployread":self.key_deployread, "otheruser":self.key_otheruser, "anonymous":None}[key], self.repo, **self.kwargs)
        h = x.getauthheader(action)
        del h["Content-Type"]
        if self.overrideurl["download"]:
            url = self.overrideurl["download"].format(sshtarget=self.sshtarget, repo=self.repo, sha256=sha256, size=size)
            assert self.verifydownload, "must verifydownload when overrideurl enabled"
        else:
            u=x.get_download_url(sha256, size, action=action)
            url = u["actions"]["download"]["href"]
            h.update(u["actions"]["download"].get("header",{}))
        print(url, h)
        assert url.startswith("http")
        if self.verifydownload: #need to download the file and check content matching sha256
            h.update(self.download_force_header)
            if "Authorization" in h:
                h["Authorization"] = h["Authorization"].strip()
            f = sess.get(url, headers=h)
            debugprint(f, raw=True)
            assert f.status_code==200, (f, f.text)
            contentsha256 = hashlib.sha256(f.content).hexdigest()
            assert sha256==contentsha256
            print("verify download ok", sha256)

    def test4_otheruser_read(self, sha256, action="download"): #public repo
        return self.test3_download_process(sha256, key="otheruser", action=action)

    def test5_otheruser_upload(self, action="upload", doverify=True):
        return self.test2_upload_process("otheruser", action=action, doverify=doverify)

    def test6_otheruser_upload_usedownloadtoken(self):
        return self.test5_otheruser_upload(action="download")
    
    def test7_candownload_without_verify(self, dodownload=True):
        sha256 = self.test2_upload_process(doverify=False)
        if dodownload:
            self.test3_download_process(sha256)
    
    def test8_candownload_use_uploadtoken(self, sha256):
        self.test3_download_process(sha256, action="upload")
    
    def test9_canupload_use_deployread(self, action="upload"):
        self.test2_upload_process("deployread", action, doverify=True)
    
    def test10_canupload_use_deployread_usedownloadtoken(self):
        return self.test9_canupload_use_deployread(action="download")

    def manipulated_upload(self, put_wrongcontent=False, put_wrongsize=False, verify_wrongsize=False, key="readwrite", doverify=True):
        x = GIT_LFS(self.sshtarget, {"readwrite":self.key_readwrite, "deployread":self.key_deployread, "otheruser":self.key_otheruser, "anonymous":None}[key], self.repo, **self.kwargs)
        h = x.getauthheader("upload")

        size = 1024*1024 # 1MB
        content = os.urandom(size)
        sha256 = hashlib.sha256(content).hexdigest()
        content_changed = os.urandom(size)

        s = size
        if put_wrongsize:
            s = put_wrongsize
        actions = x.get_upload_url(sha256, s, "upload")
        url = actions["upload"]["href"]
        h.update(actions["upload"].get("header",{}))
        c = content
        if put_wrongcontent:
            c = content_changed #wrong content with same size
        file_put(url, c, h)

        if "verify" in actions and doverify:
            s = size
            if verify_wrongsize:
                s = verify_wrongsize
            x.do_verify_step(sha256, s, actions["verify"])
        print("upload ok:", sha256)
        return sha256

    def test11_putwrongcontent(self, key="readwrite", doverify=True):
        return self.manipulated_upload(put_wrongcontent=True, key=key, doverify=doverify)

    def test12_putwrongsize_smaller(self, size=1, key="readwrite", doverify=True):
        sha256 = self.manipulated_upload(put_wrongsize=size, key=key, doverify=doverify) #report 1byte with correct sha256, but upload 1MB, verify 1byte
        d = self.test3_download_process(sha256, size=size, key=key)
    
    def test13_putwrongsize_bigger(self, key="readwrite", size=10*1024*1024, doverify=True):
        return self.test12_putwrongsize_smaller(size=size, key=key, doverify=doverify)  #report 10MB with correct sha256, but upload 1MB, verify 10MB

    def test14_verifywrongsize(self, key="readwrite"):
        self.manipulated_upload(verify_wrongsize=1, key=key)
    
    def test15_upload_use_otherusertoken(self, otherrepo, doverify=True):
        action = "upload"
        myx = GIT_LFS(self.sshtarget, self.key_readwrite, self.repo, **self.kwargs)
        otherx = GIT_LFS(self.sshtarget, self.key_otheruser, otherrepo, **self.kwargs)
        h = otherx.getauthheader(action)
        size = 1024*1024 #1MB
        randomdata = os.urandom(size)
        sha256 = hashlib.sha256(randomdata).hexdigest()
        print("sha256:", sha256)
        if self.overrideurl["upload"]:
            url = self.overrideurl["upload"].format(sshtarget=self.sshtarget, repo=self.repo, sha256=sha256, size=size)
            actions = {}
            del h["Content-Type"]
        else:
            x = sess.post(myx.lfsurl, json={"operation":"upload", "objects":[{"oid":sha256, "size":size}], "ref":{ "name": "refs/heads/master"}}, headers=h)
            debugprint(x)
            d = x.json()["objects"][0]
            actions = d["actions"]
            url = actions["upload"]["href"]
            h = actions["upload"].get("header",{})
        file_put(url, randomdata, h)
        if doverify and "verify" in actions:
            otherx.do_verify_step(sha256, size, actions["verify"])
            #pass
        print("upload ok:", sha256)
        return sha256

    def test16_download_use_otherusertoken(self, otherrepo, sha256):
        action = "download"
        myx = GIT_LFS(self.sshtarget, self.key_readwrite, self.repo, **self.kwargs)
        otherx = GIT_LFS(self.sshtarget, self.key_otheruser, otherrepo, **self.kwargs)
        h = otherx.getauthheader(action)
        size = 1024*1024 #1MB
        if self.overrideurl["download"]:
            url = self.overrideurl["download"].format(sshtarget=self.sshtarget, repo=self.repo, sha256=sha256, size=size)
            assert self.verifydownload, "must verifydownload when overrideurl enabled"
            del h["Content-Type"]
        else:
            x = sess.post(myx.lfsurl, json={"operation":"download", "objects":[{"oid":sha256, "size":size}], "ref":{ "name": "refs/heads/master"}}, headers=h)
            debugprint(x)
            d = x.json()["objects"][0]
            url = d["actions"]["download"]["href"]
            h = d["actions"]["download"].get("header", {})
        print(url)
        assert url.startswith("http")
        if self.verifydownload: #need to download the file and check content matching sha256
            f = sess.get(replaceurl(url), headers=h)
            assert f.status_code==200, (f, f.text)
            contentsha256 = hashlib.sha256(f.content).hexdigest()
            assert sha256==contentsha256
            print("verify download ok", sha256)

    def test17_crossrepo_download(self, otherrepo, sha256, **kwargs):
        kw = self.kwargs.copy()
        kw.update(kwargs)
        otherx = GIT_LFS(self.sshtarget, self.key_otheruser, otherrepo, **kw)
        h = otherx.getauthheader("download")
        size = 1024*1024 #1MB
        if self.overrideurl["download"]:
            url = self.overrideurl["download"].format(sshtarget=self.sshtarget, repo=otherrepo, sha256=sha256, size=size)
            assert self.verifydownload, "must verifydownload when overrideurl enabled"
            del h["Content-Type"]
        else:
            x = sess.post(otherx.lfsurl, json={"operation":"download", "objects":[{"oid":sha256, "size":size}], "ref":{ "name": "refs/heads/master"}}, headers=h)
            debugprint(x)
            d = x.json()["objects"][0]
            url = d["actions"]["download"]["href"]
            h = d["actions"]["download"].get("header", {})
        print(url)
        assert url.startswith("http")
        if self.verifydownload: #need to download the file and check content matching sha256
            f = sess.get(replaceurl(url), headers=h)
            debugprint(f)
            assert f.status_code==200, (f, f.text)
            contentsha256 = hashlib.sha256(f.content).hexdigest()
            assert sha256==contentsha256
            print("verify download ok", sha256)

