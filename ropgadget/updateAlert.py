## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
## 
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.

import re
try:
    import httplib
except ImportError:
    import http.client as httplib


from ropgadget.version import *


class UpdateAlert(object):

    @staticmethod
    def checkUpdate():
        try:
            conn = httplib.HTTPSConnection("raw.githubusercontent.com", 443)
            conn.request("GET", "/JonathanSalwan/ROPgadget/master/ropgadget/version.py")
        except:
            print("Can't connect to raw.githubusercontent.com")
            return
        d = conn.getresponse().read()
        majorVersion = re.search("MAJOR_VERSION.+=.+(?P<value>[\d])", d).group("value")
        minorVersion = re.search("MINOR_VERSION.+=.+(?P<value>[\d])", d).group("value")
        webVersion = int("%s%s" %(majorVersion, minorVersion))
        curVersion = int("%s%s" %(MAJOR_VERSION, MINOR_VERSION))
        if webVersion > curVersion:
            print("The version %s.%s is available. Currently, you use the version %d.%d." %(majorVersion, minorVersion, MAJOR_VERSION, MINOR_VERSION))
        else:
            print("Your version is up-to-date.")

