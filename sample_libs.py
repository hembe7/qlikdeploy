# coding: utf-8
import json
import os, sys, time
from collections import OrderedDict

if sys.version_info > (3,):
	print('Using environment Python 3.X\n')
else:
	print('Using environment Python 2.X\n')

class SampleLibsProgram(object):
	
	def list_Libs(self, env):
		file = open("./source_libs.json", mode="r", encoding="utf-8")
		line = file.read()
		file.close()
		finalstring = ''.join(line)
		json_data = json.loads(finalstring, object_pairs_hook=OrderedDict)

		task_file = open("./tasks/Test-New-Cluster__2021-08-27--16-12-22-887071.json", mode="r", encoding="utf-8")
		task_line = task_file.read()
		task_file.close()
		# print(task_line)
		# taskfinalstring = ''.join(task_line)
		# json_data = json.loads(taskfinalstring, object_pairs_hook=OrderedDict)

		lib_list = json_data['libs']
		for lib in lib_list:
			#print("Find and Replace {0} with {1}".format(lib['DEV'], lib[env]) )
			task_line = task_line.replace(lib['DEV'], lib['UAT'])
		print(task_line)
	#end SampleLibsProgram list_Libs

sample = SampleLibsProgram()
sample.list_Libs("UAT")