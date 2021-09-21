# coding: utf-8
import os, sys, time
from collections import OrderedDict

# import AEM-Client
from aem_client import *

if sys.version_info > (3,):
	print('Using environment Python 3.X\n')
else:
	print('Using environment Python 2.X\n')

# Utility class for Examples
class Utils(object):
	@staticmethod
	def dollar_type(obj):
		"""
		get attribute '$type'
		"""
		return getattr(obj, '$type')
	# Utils.dollar_type

	@staticmethod
	def enum_name(enum_val):
		return enum_val.name
	# Utils.enum_name

	@staticmethod
	def print_action_title(action_text):
		print('\n############################################################')
		print('\n{0}\n'.format(str(action_text) ) )
	# Utils.print_action_title
	
	@staticmethod
	def print_action_title_without_separator(action_text):
		print('\n{0}\n'.format(str(action_text) ) )
	# Utils.print_action_title_without_separator
	
	@staticmethod
	def time_sleep(duration=3, show_msg=True):
		"""
		sleep for duration (in seconds)
		"""
		if show_msg:
			print('Sleeping for: {0} seconds'.format(duration))
		time.sleep(duration)
	# Utils.time_sleep

	@staticmethod
	def get_b64_user_pass(username, password):
		"""
		return a base64 of 'username:password'
		"""
		username_password_str = str.encode('{0}:{1}'.format(username, password))
		return base64.b64encode(username_password_str).decode('ascii')
	# Utils.get_b64_user_pass

	@staticmethod
	def changed_initial(current_value, predefine_value, param_name):	
		if current_value == predefine_value:
			raise Exception('Please replace param: "{0}", value:"{1}", to the real value.'.format(param_name, predefine_value ) )
	# Utils.changed_initial

	@staticmethod
	def print_dict_attr(obj, attr_name):
		for key in obj.__dict__:
			item = obj.__dict__[key]					
			if hasattr(item, attr_name):
				inner_list = getattr(item,attr_name)
				for inner_item in inner_list:
					print('\t{0}:\t{1}'.format(inner_item.name, key))
	# Utils.print_dict_attr
# END of class Util

class QlikDeployProgram(object):
	def __init__(self, ):
				
		### you can use the environment for username and password
		#Get user_name and password from environment			
		# username = os.getenv("AEM_USERNAME", default=None)
		# print('AEM_USERNAME = ' + env_username)
		# password = os.getenv("AEM_PASSWORD", default=None)
		# print('AEM_PASSWORD = ' + env_password)

		### Information for connecting to AEM (replace placeholders with actual connection details)
		# domain = 'PRUASIA'
		# username = '382078'
		# password = 'welcome@plt1'
		# aem_machine_name = 'thlifelz1sobv8v.pru.intranet.asia'

		domain = 'qlikdemoint'
		username = 'qlikadmn'
		password = 'P@ssword123456'
		aem_machine_name = 'qlikdemoint'
		Utils.changed_initial(domain, 'DOMAIN', 'domain')
		Utils.changed_initial(username, 'USER', 'username')
		Utils.changed_initial(password, 'PASSWORD', 'password')
		Utils.changed_initial(aem_machine_name, 'some-host', 'aem_machine_name')
		# Combine domain and user name - domain\\username
		domain_username = '{0}\\{1}'.format(domain, username)	
		task_name = ""
		print('Connecting to AemClient with user "{0}" on machine name: "{1}"...'.format(domain_username, aem_machine_name))
		try:
			# The format of credentials AemClient must get is domain\\username:password base64 encoded
			b64_username_password = Utils.get_b64_user_pass(domain_username, password)
			# Create an instance of AemClient
			self.aem_client = AemClient(b64_username_password, aem_machine_name, verify_certificate=False)
			print('Done.')			
			print('\n############################################################')
		except Exception as ex:
			print('Failed connecting to AemClient')
			print(ex)	
			self.aem_client = None
	# end function __init__ for QlikDeployProgram

	def get_server_list_and_print(self, print_list = False):		
		resp = self.aem_client.get_server_list()		
		# serverList, taskList, endpointList - are the only-one in camelCase
		if resp and resp.serverList:			
			if print_list:  
				print(str( len(resp.serverList) ) +' server found')
				print('For each server showing [Name, Type, Version, State, Message]:\n')				
				for server in resp.serverList:				
					print('\t[{0}, {1}, {2}, {3}, {4}]'.format(server.name, Utils.dollar_type(server), server.version, Utils.enum_name(server.state), server.message ) )   
			return resp.serverList
		else:
			print('0 server found')
			return []		
	# end function get_server_list_and_print

	def add_server_if_not_exist(self, server_name, host, port=443, username=None, password=None, description=None, monitored=True):
		#Checking existence of server "server_name" (calling method get_server)
		try:
			resp = self.aem_client.get_server(server_name)
			if resp:
				print('Server exists\n')			
		except AemClientException as ex:
			"""
				If AemClientException was triggered, verify that the exception property error_code matches your error code expected behavior
			"""
			if ex.error_code == 'AEM_SERVER_NOT_FOUND':				
				print('Server does not exist (method get_server returned AEM_SERVER_NOT_FOUND, The requested server "{0}" could not be found.)'.format(server_name) )
				print('Adding server "{0}" to AEM (calling method put_server)'.format(server_name))
				self.put_server_replicate(server_name, host, port, username, password, description, monitored)
			else:
				raise ex		
	# end function add_server_if_not_exist

	def	put_server_replicate(self, name, host, port=443, username=None, password=None, description=None, monitored=True):
		# Add new Replicate server
		replicate_server = AemReplicateServer()
		replicate_server.name = name		
		replicate_server.host = host
		replicate_server.port = port
		replicate_server.username = username		
		replicate_server.password = password
		replicate_server.description = description
		replicate_server.monitored = monitored
		try:
			self.aem_client.put_server(replicate_server, replicate_server.name)
		except Exception as ex:
			print('Error: in aem_put_server')
			print(ex)
	# end function put_server_replicate

	def is_server_in_aem(self, server_name):
		serverList = self.get_server_list_and_print(print_list=False)
		# serverList, taskList, endpointList - are the only-one in camelCase
		if not serverList:
			return False
		server_matches = [item for item in serverList if item.name == server_name] 
		return len(server_matches) > 0
	# end function is_server_in_aem

	def put_license_to_servers(self, server_names_list, license_file_name):
		if not os.path.exists(license_file_name):
			raise Exception('License file: "{0}" not exist.'.format(license_file_name))
		try:			
			license_file_handler = open(license_file_name, 'r') 
			license_stream = license_file_handler.read()
			for server_name in server_names_list:
				self.aem_client.put_server_license(license_stream, server_name)				
			license_file_handler.close()
		except Exception as ex:
			print(ex)	
	# end function put_license_to_servers

	def print_server_details(self, server_names_list):		
		try:
			for server_name in server_names_list:
				resp = self.aem_client.get_server_details(server_name)
				print('')
				print('Server "{0}" details:'.format(server_name))
				details = resp.server_details
				print('\tName:\t\t{0}'.format(details.name))
				print('\tType:\t\t{0}'.format( Utils.dollar_type(details) ) )
				print('\tHost:\t\t{0}'.format( details.configuration.host ) )
				print('\tVersion:\t{0}'.format( details.version ) )
				print('\tState:\t\t{0}'.format( Utils.enum_name(details.state) ) )
				print('\tMessage:\t{0}'.format( details.message ) )
				print('\tLast Connection: {0}'.format( details.last_connection ) )
				print('\tTotal Tasks:\t{0}'.format( details.task_summary.total ) )
				print('\tCPU (%):\t{0}'.format( details.resource_utilization.machine_cpu_percentage ) )
		except Exception as ex:
			print('Get Server Details exception')
			print(ex)	
	# end function print_server_details

	def overwrite_server_acl(self, server_name, admin_users=None, designer_users=None, operator_users=None, viewer_users=None, none_users=None, viewer_groups=None):
		temp_acl = AemAuthorizationAcl()
		if admin_users:
			temp_acl.admin_role = AemRoleDef()
			for admin in admin_users:
				aem_admin = AemUserRef()
				aem_admin.name = admin
				temp_acl.admin_role.users.append(aem_admin)
		if designer_users:
			temp_acl.designer_role = AemRoleDef()
			for designer in designer_users:
				aem_designer = AemUserRef()
				aem_designer.name = designer
				temp_acl.designer_role.users.append(aem_designer)
		if operator_users:
			temp_acl.operator_role = AemRoleDef()
			for operator in operator_users:
				aem_operator = AemUserRef()
				aem_operator.name = operator
				temp_acl.operator_role.users.append(aem_operator)
		if viewer_users or viewer_groups:
			temp_acl.viewer_role = AemRoleDef()
			if viewer_users:
				for viewer in viewer_users:
					aem_viewer = AemUserRef()
					aem_viewer.name = viewer
					temp_acl.viewer_role.users.append(aem_viewer)
			if viewer_groups:
				for group_viewer in viewer_groups:
					aem_viewer_group = AemGroupRef()
					aem_viewer_group.name = group_viewer
					temp_acl.viewer_role.groups.append(aem_viewer_group)
		self.aem_client.put_server_acl(temp_acl, server_name)
		print('Done')		
	# end function overwrite_server_acl

	def get_server_acl(self, name, print_acl=False):
		#resp = AemAuthorizationAcl
		try:
			resp = self.aem_client.get_server_acl(name)
			if print_acl and resp:
				print('')
				print('ACL for Server "{0}":'.format(name))
				print('Users:')
				Utils.print_dict_attr(resp, 'users')
				print('Groups:')
				Utils.print_dict_attr(resp, 'groups')
				inherit = not resp.disable_inheritance
				print('Inherit:\t{0}\n'.format(inherit) )
			return resp
		except Exception as ex:
			print(ex)	
			return None
	# end function get_server_acl

	def get_task_list_and_print(self, server_name, print_list=False):
		resp = self.aem_client.get_task_list(server_name)	
		if print_list and resp:
			print(str( len(resp.taskList) ) +' task(s) found')
			print('For each task show [Name, State, Stop Reason]:\n')			
			for task in resp.taskList:
				print('\t[{0}, {1}, {2}]'.format(task.name, Utils.enum_name(task.state), Utils.enum_name(task.stop_reason) ) )
		return resp.taskList
	# end function get_task_list_and_print

	#SET that executing import, override and then export task
	
	def export_task_json(self, server, task, withendpoints=True):
		if self.is_task_in_server(task, server):
			try:
				resp_stream = self.aem_client.export_task(server, task, withendpoints)
				str_decoded = resp_stream.decode('utf-8')
				print('Done.\n')
				return str_decoded
			except Exception as ex:
				print(ex)
				print('Error: aem_export_task\n')				
				return None			
		else:			
			print('Error: Task "{0}" is NOT in server: "{1}"\n...'.format(task, server))			
	# end of function export_task_json

	def change_task(self, task, new_name, new_src_usrnm, new_src_pwr,new_src_svr, new_src_jrnnm, new_src_jrnlib,  new_trg_tkn, new_trg_db, new_trg_stgdir, new_trg_hvodbchst, new_trg_httpath, new_trg_adlsacct, new_trg_adlstntid, new_trg_adlsappid, new_trg_adlsappkey, new_trg_filesys):
		if not task:
			raise Exception('task is empty.')
			return None
		try:			
			### Remove the .net like remark (e.g // Host name: SK2016.qa.int, Time: 2018-07-31 16:38:14.044075) as Python does not read it right when trying to load as JSON.
			strings = task #task.splitlines(True) 
			#strings.pop(0)
			finalstring = ''.join(strings)
			
			### Renamed task
			print('Updating task settings:')
			print('Update name to be "{0}"'.format(new_name) )
			
			#use OrderedDict
			json_data = json.loads(finalstring, object_pairs_hook=OrderedDict)

			# json_data['cmd.replication_definition']['tasks'][0]['task']['name'] = new_name 
			self.task_name = json_data['cmd.replication_definition']['tasks'][0]['task']['name']
			### Change Endpoints passwords
			### Source			
			print('Update source endpoint password')
			json_data['cmd.replication_definition']['databases'][0]['db_settings']['username'] = new_src_usrnm
			json_data['cmd.replication_definition']['databases'][0]['db_settings']['password'] = new_src_pwr
			json_data['cmd.replication_definition']['databases'][0]['db_settings']['server'] = new_src_svr
			json_data['cmd.replication_definition']['databases'][0]['db_settings']['JournalName'] = new_src_jrnnm
			json_data['cmd.replication_definition']['databases'][0]['db_settings']['JournalLibrary'] = new_src_jrnlib

			### Target
			print('Update target endpoint password') 
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['password'] = new_trg_tkn
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['database'] = new_trg_db
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['stagingdirectory'] = new_trg_stgdir
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['hiveODBCHost'] = new_trg_hvodbchst
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['httpPath'] = new_trg_httpath
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['adlsstorageaccountname'] = new_trg_adlsacct
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['adlstenantid'] = new_trg_adlstntid
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['adlsclientappid'] = new_trg_adlsappid
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['adlsclientappkey'] = new_trg_adlsappkey
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['filesystem'] = new_trg_filesys

			### add new table (replace owner and table name with real names)
			# print('Adding table "dbo.table1"')
			# new_table = {}
			# new_table['owner'] = 'dbo'
			# new_table['name'] = 'table1'
			# #new_table['description'] = 'Description for: {0}.{1}'.format(new_table['owner'], new_table['name'] )
			# tables = json_data['cmd.replication_definition']['tasks'][0]['source']['source_tables']['explicit_included_tables']
			# tables.append(new_table)
			# print('')			
			return json_data
		except Exception as ex:
			print('error')
			print(ex)	
			return None	
	# end of function change_task

	def verify_if_task_run_stop_it(self, server_name, task_name):
		print('Before import, stopping task "{0}" if exists and running on target server "{1}".'.format(task_name, server_name))
		resp_tasks = self.aem_client.get_task_list(server_name)
		for task in resp_tasks.taskList:
			if task.name == task_name and task.state == AemTaskState.RUNNING:
				self.aem_client.stop_task(server_name, task_name) 
				return None
	
	def import_task_into_server(self, json_data, server_name, task_name):
		if not json_data:
			raise Exception("No data in json_data")
		self.verify_if_task_run_stop_it(server_name, task_name)
		try:
			data_in_string = json.dumps(json_data)
			self.aem_client.import_task(data_in_string, server_name, task_name)			
		except Exception as ex:
			print(ex)
			print('Error: import_task')
	# end of function import_task

	def is_task_in_server(self, task_name, server_name):
		taskList_i = self.get_task_list_and_print(server_name, print_list=False)		
		### serverList, taskList, endpointList - are the only-one in camelCase
		if not taskList_i:
			return False
		task_matches = [task for task in taskList_i if task.name == task_name]
		return len(task_matches) > 0
	# end of function is_task_in_server

	def run_task(self, server, taskname, option=AemRunTaskOptions.RESUME_PROCESSING):
		reqAemRunTask = AemRunTaskReq()
		try:
			self.aem_client.run_task(reqAemRunTask, server, taskname, option)
		except Exception as ex:
			print('Run Task "{0}" error'.format(taskname) )
			print(ex)
	# end function run_task

	def get_task_details(self, server, task, print_info=False):
		try:
			resp = self.aem_client.get_task_details(server, task)
			details = resp.task
			### details is of class AemTaskInfoDetailed
			if print_info:
				print('Details of "{0}" on server "{1}":'.format(task, server) )
				print('\tState: {0}'.format( Utils.enum_name(details.state) )	)							
				print('\tTables with Error:{0}'.format(details.full_load_counters.tables_with_error_count) ) 
				print('\tFL Target Throughput (rec/sec): {0}'.format(details.full_load_throughput.target_throughput_records_count) )
				print('\tApply Latency: {0}'.format(details.cdc_latency.total_latency) )						
				if details.task_stop_reason:
					print('\tStop reason: {0}'.format(Utils.enum_name(details.task_stop_reason) ) )
			return details
		except Exception as ex:
			print('Error aem_get_task_details')
			print(ex)
			return None
	# end function get_task_details

	def wait_task_details(self, server_name, task_name, max_try=10):
		for index in range(max_try):
			try:
				resp = self.aem_client.get_task_details(server_name, task_name)
				return resp.task
			except Exception as ex:				
				if index >= max_try:
					print(ex)
					raise Exception(ex)	
				print('.')				
				Utils.time_sleep(1, show_msg=False)
		return None
	# end function wait_task_details
	def change_lib(self, taskstr):
		file = open("./source_libs.json", mode="r", encoding="utf-8")
		line = file.read()
		file.close()
		finalstring = ''.join(line)
		json_data = json.loads(finalstring, object_pairs_hook=OrderedDict)
		lib_list = json_data['libs']
		for lib in lib_list:
			#print("Find and Replace {0} with {1}".format(lib['DEV'], lib[env]) )
			taskstr = taskstr.replace(lib['DEV'], lib['UAT'])
		return taskstr
	# end function change_lib	
# END class QlikDeployProgram


#################################
#		qlikdeploy_main			#
#################################
def qlikdeploy_main():

	 # setup_aem_client
	qlik_program = QlikDeployProgram()
	# if qlik_program.aem_client == None:
	# 	print('Error: in aem_client,\nExiting.')
	# 	return
	
	### print get_server_list
	Utils.print_action_title_without_separator('Getting AEM server list (calling method get_server_list)')
	qlik_program.get_server_list_and_print(print_list=True)

	### Add server if not exist
	# replicate_server_name = '#{replicate_server_name}#'
	# replicate_host = '#{replicate_host}#'
	replicate_server_name = 'QlikDemoIntServer'
	replicate_host = 'qlikdemoint'

	### username => Replicate: DOMAIN\\USER (replace placeholders with actual logical server names)
	# replicate_username = '#{replicate_username}#'
	# replicate_password = '#{replicate_password}#'
	replicate_username = 'qlikdemoint\\qlikadmn'
	replicate_password = 'P@ssword123456'

	Utils.changed_initial(replicate_host, 'some.host.com', 'replicate_host')
	Utils.changed_initial(replicate_username, 'username', 'replicate_username')
	Utils.changed_initial(replicate_password, 'password', 'replicate_password')

	Utils.print_action_title('Checking existence of server "{0}"'.format(replicate_server_name))
	qlik_program.add_server_if_not_exist(replicate_server_name, replicate_host, username=replicate_username, password=replicate_password)	

	### print_server_details
	print('Getting server details (calling method get_server_details)')
	Utils.time_sleep(3, show_msg=False)
	qlik_program.print_server_details([replicate_server_name])

	## import tasks
	path = './tasks'

	for root, directories, files in os.walk(path, topdown=False):
		for name in files:
			task_file = os.path.join(root, name)
	
			print("File name: {}".format(name))
			file = open(task_file, mode="r", encoding="utf-8")
			line = file.read()
			file.close()
			### Change lib or schema
			line = qlik_program.change_lib(line)
			json_result = qlik_program.change_task(line, 
								"Test-New-Cluster", 
								"DLDEV",
								"Q1w2e3r4", 
								"PLTDEV", 
								"DLAKEJRN", 
								"$OLLIB", 
								"new_trg_tkn", 
								"new_trg_db", 
								"new_trg_stgdir", 
								"new_trg_hvodbchst", 
								"new_trg_httpath", 
								"new_trg_adlsacct", 
								"new_trg_adlstntid", 
								"new_trg_adlsappid", 
								"new_trg_adls_appkey", 
								"new_trg_filesys")
			print("TASK NAME: {}".format(qlik_program.task_name))
			# print(json_result)
			qlik_program.import_task_into_server(json_result, server_name="QlikDemoIntServer", task_name=qlik_program.task_name)
			print('.')				
			Utils.time_sleep(10, show_msg=False)
			is_task_insvr = qlik_program.is_task_in_server(task_name=qlik_program.task_name, server_name="QlikDemoIntServer")
			print("Task {0} has deployed in server: {1}".format(qlik_program.task_name, is_task_insvr))
	print('\nDONE.')
### END of function MAIN_USE
##############################################################


if __name__ == '__main__':
	qlikdeploy_main()
