"""
Copyright 2018 Attunity
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

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

class ExamplePythonProgram(object):
	def __init__(self, ):
		"""		
		### you can use the environment for username and password
		#Get user_name and password from environment			
		username = os.getenv("AEM_USERNAME", default=None)
		print('AEM_USERNAME = ' + env_username)
		password = os.getenv("AEM_PASSWORD", default=None)
		print('AEM_PASSWORD = ' + env_password)
		"""

		### Information for connecting to AEM (replace placeholders with actual connection details)
		domain = 'DOMAIN'
		username = 'USER'
		password = 'PASSWORD'
		aem_machine_name = 'some-host'

		Utils.changed_initial(domain, 'DOMAIN', 'domain')
		Utils.changed_initial(username, 'USER', 'username')
		Utils.changed_initial(password, 'PASSWORD', 'password')
		Utils.changed_initial(aem_machine_name, 'some-host', 'aem_machine_name')
		# Combine domain and user name - domain\\username
		domain_username = '{0}\\{1}'.format(domain, username)	

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
	# end function __init__ for ExamplePythonProgram

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

	def change_task(self, task, new_name, new_src_pwr, new_trg_pwr):
		if not task:
			raise Exception('task is empty.')
			return None
		try:			
			### Remove the .net like remark (e.g // Host name: SK2016.qa.int, Time: 2018-07-31 16:38:14.044075) as Python does not read it right when trying to load as JSON.
			strings = task.splitlines(True) 
			strings.pop(0)
			finalstring = ''.join(strings)

			### Renamed task
			print('Updating task settings:')
			print('Update name to be "{0}"'.format(new_name) )
			
			#use OrderedDict
			json_data = json.loads(finalstring, object_pairs_hook=OrderedDict)

			json_data['cmd.replication_definition']['tasks'][0]['task']['name'] = new_name 

			### Change Endpoints passwords
			### Source			
			print('Update source endpoint password')
			json_data['cmd.replication_definition']['databases'][0]['db_settings']['password'] = new_src_pwr
			### Target
			print('Update target endpoint password') 
			json_data['cmd.replication_definition']['databases'][1]['db_settings']['password'] = new_trg_pwr

			### add new table (replace owner and table name with real names)
			print('Adding table "dbo.table1"')
			new_table = {}
			new_table['owner'] = 'dbo'
			new_table['name'] = 'table1'
			#new_table['description'] = 'Description for: {0}.{1}'.format(new_table['owner'], new_table['name'] )
			tables = json_data['cmd.replication_definition']['tasks'][0]['source']['source_tables']['explicit_included_tables']
			tables.append(new_table)
			print('')			
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
# END class ExamplePythonProgram


#################################
#		example_main			#
#################################
def example_main():

	# setup_aem_client
	example_program = ExamplePythonProgram()
	if example_program.aem_client == None:
		print('Error: in aem_client,\nExiting.')
		return
	
	### print get_server_list
	Utils.print_action_title_without_separator('Getting AEM server list (calling method get_server_list)')
	example_program.get_server_list_and_print(print_list=True)

	### Add server if not exist
	replicate_server_name = 'Replicate Server1'
	replicate_host = 'some.host.com'
	
	### username => Replicate: DOMAIN\\USER (replace placeholders with actual logical server names)
	replicate_username = 'username'
	replicate_password = 'password'

	Utils.changed_initial(replicate_host, 'some.host.com', 'replicate_host')
	Utils.changed_initial(replicate_username, 'username', 'replicate_username')
	Utils.changed_initial(replicate_password, 'password', 'replicate_password')

	Utils.print_action_title('Checking existence of server "{0}"'.format(replicate_server_name))
	example_program.add_server_if_not_exist(replicate_server_name, replicate_host, username=replicate_username, password=replicate_password)	

	### put_license_to_servers
	print('Registering server license (calling method put_server_license)')

	### Get the Replicate license from file (replace license_file with real license file name)
	license_file_name = 'license_file'
	
	Utils.changed_initial(license_file_name, 'license_file', 'license_file_name')	
	### Register the license to Replicate server
	example_program.put_license_to_servers([replicate_server_name], license_file_name)

	### print_server_details
	print('Getting server details (calling method get_server_details)')
	Utils.time_sleep(3, show_msg=False)
	example_program.print_server_details([replicate_server_name])

	### PUT server ACL
	Utils.print_action_title('Putting ACL for server "{0}" (calling method put_server_acl)...'.format(replicate_server_name) )
	
	### Users and groups in different Roles (replace with real users and groups)
	admin_users = ['domain\\admin1']
	viewer_users = ['domain\\viewer321', 'domain\\viewer331','domain\\viewer332','domain\\viewer333']
	viewer_groups = ['domain\\group_basic_001']	
	example_program.overwrite_server_acl(replicate_server_name, admin_users, viewer_users=viewer_users, viewer_groups=viewer_groups)

	### GET server ACL
	print('Getting ACL for server "{0}" (calling method get_server_acl)'.format(replicate_server_name) )	
	example_program.get_server_acl(replicate_server_name, print_acl=True)

	### print task list
	Utils.print_action_title('Getting tasks for server "{0}" (calling method get_task_list)'.format(replicate_server_name) )	
	example_program.get_task_list_and_print(replicate_server_name, print_list=True)			

	### Export task (replace task_name with real task name)
	task_name = 'move_data101'
	Utils.changed_initial(task_name, 'move_data101', 'task_name')
	### example_program.export_task_json returns the exported task JSON as string
	Utils.print_action_title('Exporting task "{0}" on server "{1}" with endpoints (calling method export_task)...'.format(task_name, replicate_server_name) )
	decoded_task = example_program.export_task_json(replicate_server_name, task_name)	 
	
	### New task name to import to the other server, source and target endpoint passwords
	new_task_name = 'move_data101_production'
	new_src_psw = 'source-new-password'
	new_trg_psw = 'target-new-password'
	Utils.changed_initial(new_task_name, 'move_data101_production', 'new_task_name')
	Utils.changed_initial(new_src_psw, 'source-new-password', 'new_src_psw')
	Utils.changed_initial(new_trg_psw, 'target-new-password', 'new_trg_psw')
	json_data = example_program.change_task(decoded_task, new_task_name, new_src_psw, new_trg_psw) 

	other_replicate = 'Replicate-S002'

	Utils.changed_initial(other_replicate, 'Replicate-S002', 'other_replicate')
	### Import task into second server B
	print('Importing task "{0}" to server "{1}" (calling method import_task)...'.format(new_task_name, other_replicate) ) 
	example_program.import_task_into_server(json_data, other_replicate, new_task_name)
	print('')

	### Wait for server finish import
	print('Verifying task was imported...')
	example_program.wait_task_details(other_replicate, new_task_name)
	
	### Run Task	
	print('Running task "{0}" on server "{1}" (calling method run_task)...'.format(new_task_name, other_replicate) )	
	example_program.run_task(other_replicate, new_task_name)
	
	### Print task details 
	Utils.print_action_title_without_separator('Getting task details (calling method get_task_details)')	
	example_program.get_task_details(other_replicate, new_task_name, print_info=True)
	
	print('\nDONE.')
### END of function MAIN_USE
##############################################################


if __name__ == '__main__':
	example_main()
