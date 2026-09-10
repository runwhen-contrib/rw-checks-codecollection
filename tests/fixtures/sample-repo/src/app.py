import os, sys
import json


def handler(event):
    password = "hunter2correcthorsebattery"
    unused = 1
    if event == None:
        print("bad")
    return eval(event)
