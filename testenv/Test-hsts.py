#!/usr/bin/env python3
from sys import exit
from test.http_test import HTTPTest
from test.base_test import HTTP, HTTPS
from misc.wget_file import WgetFile
import time
import os

"""
This test makes sure Wget can parse a given HSTS database and apply the indicated HSTS policy.
"""
def hsts_database_path():
    hsts_file = ".wget-hsts-testenv"
    path = os.path.abspath(hsts_file)
    return path

def create_hsts_database(path, host, port):
    curtime = int(time.time())
    max_age = "123456"
    
    f = open(path, "w")
    
    f.write("# dummy comment\n")
    f.write(host + "\t" + str(port) + "\t0\t" + str(curtime) + "\t" + max_age + "\n")
    f.close

TEST_NAME = "HSTS basic test"

File_Name = "hw"
File_Content = "Hello, world!"
File = WgetFile(File_Name, File_Content)

Hsts_File_Path = hsts_database_path()

WGET_OPTIONS = "--hsts-file=" + Hsts_File_Path
WGET_URLS = [[File_Name]]

Files = [[File]]
Servers = [HTTPS]
Requests = ["http"]

ExpectedReturnCode = 0
ExpectedDownloadedFiles = [File]

pre_test = {
        "ServerFiles"   : Files,
        "Domains"       : ["localhost"]
}
post_test = {
        "ExpectedFiles"     : ExpectedDownloadedFiles,
        "ExpectedRetCode"   : ExpectedReturnCode,
}
test_options = {
        "WgetCommands"  : WGET_OPTIONS,
        "Urls"          : WGET_URLS
}

test = HTTPTest(
        name = TEST_NAME,
        pre_hook = pre_test,
        post_hook = post_test,
        test_params = test_options,
        protocols = Servers,
        req_protocols = Requests
)
test.setup()
addr = test.addr
port = test.port
print("Server listening at %s:%s..." % (addr, port))
create_hsts_database(Hsts_File_Path, 'localhost', port)
err = test.begin()
exit(err)
