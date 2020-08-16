#import and specify a reference variable name
import importtestdeclaration as itdinstance

#uses import of line #1 of importtestdeclaration.py
itdinstance.commandexec("echo 1")

#uses import of line #2 of importtestdeclaration.py
itdinstance.os.system("echo 2")

#uses import of line #3 of importtestdeclaration.py
itdinstance.test.system("echo 3")

#uses import of line #4 of importtestdeclaration.py
itdinstance.test.internalcomandexec("echo 4")

#uses import of line #5 of importtestdeclaration.py
itdinstance.test.os.system("echo 5")
