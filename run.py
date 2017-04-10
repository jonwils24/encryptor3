#!/usr/bin/python

import time

x = 0
while True:
    print("Up for {} minutes".format(str(x * 5)))
    x += 1
    time.sleep(300)