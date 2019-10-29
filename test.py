# # Python 3 program to demonstrate subprocess 
# # module 

# import subprocess 
# import os 

# def excuteC(): 
# 	s = subprocess.check_call("echo HELLO", shell = True) 
# 	print(", return code", s) 

# # Driver function 
# if __name__=="__main__": 
# 	excuteC()	 

import os
try:
	x = os.popen("gfds")
	print(x.read())
except expression as identifier:
	print(";lkjhgfd")