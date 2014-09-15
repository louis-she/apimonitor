#!/usr/bin/python
# -*- coding: utf8 -*-
import pycurl
import StringIO
import ConfigParser
import time
import sys
import re
import json
import fcntl
import os
import schedule
from urllib2 import quote

class ApiMonitor:

    def __init__(self, config_file):
        self.config = ConfigParser.ConfigParser()
        self.config.read(config_file)
        self.pidfile = self.config.get("core", "pid")
        self.entitiesConfig = self.config.sections()
        self.entitiesConfig.remove("core")
        self.entities = []

    def alert(self, msg, grade):
        data = { 
            "title": quote(msg),
            "service": "api",
            "checkpoint": "apimonitor",
            "content": quote(msg),
            "grade": grade, 
            "cluster": "public"
        }
        ldata = [row + "=" + str(data[row]) for row in data.keys() ]

        curl = pycurl.Curl()
        si = StringIO.StringIO()
        curl.setopt(pycurl.TIMEOUT, 5)
        curl.setopt(pycurl.URL, "http://alerturl/new/?{param}"\
        .format(param="&".join(ldata)))
        curl.setopt(pycurl.WRITEFUNCTION, si.write)
        curl.perform()
        curl.close()

    def log(self, msg):
        logfd = open(self.config.get("core", "log"), "a")
        nowtime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        logfd.write("[%s] %s\n" % (nowtime, msg))
        logfd.close()

    def run(self):
        for entityConfig in self.entitiesConfig:
            entityConfigObj = {"module": entityConfig}
            for keypair in self.config.items(entityConfig):
                entityConfigObj.update({keypair[0]: keypair[1]})
            entity = MonitorEntity(entityConfigObj)
            self.entities.append(entity)
        self.fork()

    def fork(self):
        fd = open(self.pidfile, "w")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        if pid == 0:
            os.setsid()
            pid1 = os.fork()
            if pid1 > 0:
                fd.write(str(pid1))
                sys.exit(0)
            if pid1 == 0:
                self.routine()
            if pid1 < 0:   
                raise Exception, "spwan process failed"

        if pid < 0:
            raise Exception, "spwan process failed"

    def routine(self):
        # install schedule
        for entity in self.entities:
            pieces = entity.getschedule().split(" ")
            if re.match("^\d*$", pieces[1]):
                every = schedule.every(int(pieces[1]))
                pieces = pieces[2:len(pieces)]
            else:
                every = schedule.every()
                pieces = pieces[1:len(pieces)]

            timedes = getattr(every, pieces[0])
            pieces = pieces[1:len(pieces)]

            if len(pieces) and pieces[0] == "at":
                finish = timedes.at(pieces[1])
            else:
                finish = timedes

            finish.do(self.monitor, entity)

        while True:
            time.sleep(1)
            for entity in self.entities:
                schedule.run_pending()

    def monitor(self, entity):
        si = StringIO.StringIO()
        curl = pycurl.Curl()
        try:
            url = entity.geturl()
            self.log(url)

            curl.setopt(pycurl.WRITEFUNCTION, si.write)
            curl.setopt(pycurl.TIMEOUT, 5)
            curl.setopt(pycurl.URL, str(url))
            curl.perform()
            body = si.getvalue().decode(entity.charset())
            code = curl.getinfo(pycurl.HTTP_CODE)

            entity.checkCode(code)
            entity.checkBody(body)

        except pycurl.error, e:
            msg = "[{module}]curl api failed, {info}"\
                .format(info=e.args[1], module=entity.getmodule())
            self.log(msg)
            self.alert(msg, 2)
        except Exception, e:
            msg = "[{module}]api error:  {info}"\
                .format(module=entity.getmodule(), info=e.args[0])
            self.log(msg)
            self.alert(msg, 2)
        
        curl.close()
        si.close()
        entity.clear()

class MonitorEntity:

    def __init__(self, config):
        self.config = config
        self.error = ""

    def clear(self):
        self.error = ""

    def getmodule(self):
        return self.config["module"]

    def getschedule(self):
        if not self.config.has_key("schedule"):
            raise Exception, "missing schedule configure"
        return self.config["schedule"].strip()

    def geturl(self):
        if not self.config.has_key("url"):
            raise Exception, "missing url configure"
        url = self.config["url"]
        shellvalue = []
        for shellcode in re.findall("`.*?`", url):
            shellcode = "echo -n `{shellcode}`".\
                format(shellcode=shellcode[1:len(shellcode)-1])
            shellvalue.append(os.popen(shellcode).read())
        if len(shellvalue) > 0:
            url = re.sub("`.*?`", "%s", url) % tuple(shellvalue)
        return url

    def charset(self):
        if self.config.has_key("charset"):
            return self.config["charset"]
        else:
            return "utf8"

    def checkCode(self, code):
        if self.config.has_key("code"):
            expectedCode = int(self.config["code"])
        else:
            expectedCode = 200
        if code != expectedCode:
            raise Exception, "HTTP CODE {code}".format(code=code)
        return True

    def checkBody(self, body):

        if self.config.has_key("body"):
            bodyPieces = self.config["body"].strip()
        else:
            return True

        if self.config.has_key("rettype"):
            rettype = self.config["rettype"]
        else:
            rettype = "text"

        try:
            (bodyobj, oper, expect) = bodyPieces.split(" ")
        except:
            raise Exception, "body config error"
        
        thedata = ""
        if rettype == "json":
            try:
                jsonBody = json.loads(body)
            except:
                raise Exception, "Parse json failed"
            searches = re.findall("(?<=\[).*?(?=\])", bodyobj)
            try:
                for search in searches:
                    if type(jsonBody) == type([]) or type(jsonBody) == type(()):
                        search = int(search)
                    jsonBody = jsonBody[search]
                thedata = jsonBody
            except:
                raise Exception, "Wrong json data"
        elif rettype == "text":    
            thedata = body

        if oper in [">", "<"]:
            try:
                thedata = int(thedata)
            except:
                raise Exception, "response body can't convert to int"

        if oper == ">":
            if thedata <= expect:
                raise Exception, "response body {data} smaller than expected"\
                .format(data=thedata)
        elif oper == "<":
            if thedata >= expect:
                raise Exception, "response body {data} larger than expected"\
                .format(data=thedata)
        elif oper == "==":
            if str(thedata) != expect:
                raise Exception, "response body {data} not equal to expected"\
                .format(data=thedata)
        elif oper == "match":
            if not re.search(expect, thedata):
                raise Exception, "response body {data} not match expected"\
                .format(data=thedata[0:200].replace("\n", ""))
            
        return True

if __name__ == "__main__":
    if len(sys.argv) != 2 :
        print "Usage: base.py config.ini"
        exit(1)
    am = ApiMonitor(sys.argv[1])
    am.run()
