#!/usr/bin/python3

import datetime
iil = datetime.datetime(2009, 1, 1)
tt = (iil-datetime.datetime(1970,1,1)).total_seconds()
print(tt)
ttt = (datetime.utcnow()-iil).total_second()


