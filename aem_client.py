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
import os, sys, ssl, base64
from collections import OrderedDict
import json

use_python_env_3X = sys.version_info > (3,)
if use_python_env_3X:
	from urllib.parse import quote
	from urllib.request import Request, urlopen
	from urllib.error import HTTPError, URLError
	base_string_type = str
else:
	from urllib2 import Request, urlopen, HTTPError, URLError, quote
	base_string_type = basestring

HEADERS_CONTENT_TYPE = 'Content-Type'
HEADERS_CONTENT_LENGTH = 'Content-Length'

# import Enum # if 3.4 its supported in python, else use: pip install enum34
from enum import Enum


#region models

#Enums
class AemEndpointState(Enum):
	UNKNOWN = 0
	CONNECTED = 1
	ERROR = 2

class AemTableState(Enum):
	TABLE_QUEUED = 0
	TABLE_LOADING = 1
	TABLE_COMPLETED = 2
	TABLE_CHANGE_PROCESSING = 3
	TABLE_ERROR = 4

class AemPlatform(Enum):
	UNKNOWN = 0
	WINDOWS = 1
	LINUX = 2

class AemRunTaskOptions(Enum):
	RESUME_PROCESSING = 1
	RELOAD_TARGET = 2
	RESUME_PROCESSING_FROM_TIMESTAMP = 3
	METADATA_ONLY_RECREATE_ALL_TABLES = 4
	METADATA_ONLY_CREATE_MISSING_TABLES = 5
	RECOVER_USING_LOCALLY_STORED_CHECKPOINT = 6
	RECOVER_USING_CHECKPOINT_STORED_ON_TARGET = 7

class EndpointRole(Enum):
	ALL = 0
	SOURCE = 1
	TARGET = 2
	BOTH = 3

class ServerType(Enum):
	REPLICATE = 1
	COMPOSE_FDL = 3
	COMPOSE = 4
	COMPOSE_FDW = 5

class AemTaskState(Enum):
	NOT_EXIST = 0
	RUNNING = 1
	ERROR = 2
	STOPPED = 3
	PAUSED = 4
	RECOVERY = 5
	STARTING = 6
	STOPPING = 7

class AemServerState(Enum):
	NOT_MONITORED = 0
	MONITORED = 1
	ERROR = 2

class AemTaskStopReason(Enum):
	NONE = 0
	NORMAL = 1
	RECOVERABLE_ERROR = 2
	FATAL_ERROR = 3
	FULL_LOAD_ONLY_FINISHED = 4
	STOPPED_AFTER_FULL_LOAD = 5
	STOPPED_AFTER_CACHED_EVENTS = 6
	EXPRESS_LICENSE_LIMITS_REACHED = 7
	STOPPED_AFTER_DDL_APPLY = 8
	STOPPED_LOW_MEMORY = 9
	STOPPED_LOW_DISK_SPACE = 10

class AemLicenseState(Enum):
	VALID_LICENSE = 0
	INVALID_LICENSE_CHECKSUM = 1
	EXPIRED_LICENSE = 2
	NO_LICENSE = 3
	MACHINE_NOT_LICENSED = 4
	INVALID_LICENSE = 5

#Base classes
class AemServerDetails(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
			self.description = None
			self.configuration = None
			self.state = AemServerState.NOT_MONITORED
			self.message = None
			self.version = None
			self.license = None
			self.last_connection = None
			self.task_summary = None
			self.resource_utilization = None
			self.type = ServerType.REPLICATE
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.configuration = Configuration(self.configuration)
			self.state = AemServerState[self.state]
			self.license = ApiLicense(self.license)
			self.task_summary = AemTasksSummary(self.task_summary)
			self.resource_utilization = AemServerUtilization(self.resource_utilization)
			self.type = ServerType[self.type]

class AemRunTaskReq(object):
	def __init__(self, j = None):
		if not j:
			self.cdcposition = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemSetChangeDataRetentionBarrierReq(object):
	def __init__(self, j = None):
		if not j:
			self.application = None
			self.retention_point = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemTaskInfoDetailedBase(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
			self.state = AemTaskState.NOT_EXIST
			self.description = None
			self.source_endpoint = None
			self.target_endpoint = None
			self.assigned_tags = []
			self.message = None
			self.profile = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemTaskState[self.state]
			self.source_endpoint = TaskEndpoint(self.source_endpoint)
			self.target_endpoint = TaskEndpoint(self.target_endpoint)

class AemTableDetails(object):
	def __init__(self, j = None):
		if not j:
			self.schema_on_source = None
			self.table_on_source = None
			self.schema_on_target = None
			self.table_on_target = None
			self.state = AemTableState.TABLE_QUEUED
			self.data_errors_count = 0
			self.table_full_load_info = None
			self.table_cdc_info = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemTableState[self.state]
			self.table_full_load_info = AemTableFullLoadInfo(self.table_full_load_info)
			self.table_cdc_info = AemTableCdcInfo(self.table_cdc_info)

class AemTaskInfo(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
			self.state = AemTaskState.STOPPED
			self.stop_reason = AemTaskStopReason.NORMAL
			self.message = None
			self.assigned_tags = []
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemTaskState[self.state]
			self.stop_reason = AemTaskStopReason[self.stop_reason]

class AemTableInfo(object):
	def __init__(self, j = None):
		if not j:
			self.schema = None
			self.table = None
			self.state = AemTableState.TABLE_QUEUED
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemTableState[self.state]

class AemGetTableStatusesResp(object):
	def __init__(self, j = None):
		if not j:
			self.table_details = []
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			for i, k in enumerate(self.table_details):
				self.table_details[i] = AemTableDetails(self.table_details[i])

class AemRoleDef(object):
	def __init__(self, j = None):
		if not j:
			self.users = []
			self.groups = []
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			for i, k in enumerate(self.users):
				self.users[i] = AemUserRef(self.users[i])
			for i, k in enumerate(self.groups):
				self.groups[i] = AemGroupRef(self.groups[i])

class TaskEndpoint(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
			self.type = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemDeleteOldChangeDataReq(object):
	def __init__(self, j = None):
		if not j:
			self.timestamp_or_offset = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemStopTaskResp(object):
	def __init__(self, j = None):
		if not j:
			self.state = AemTaskState.NOT_EXIST
			self.error_message = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemTaskState[self.state]

class AemTableCdcInfo(object):
	def __init__(self, j = None):
		if not j:
			self.insert_count = 0
			self.update_count = 0
			self.delete_count = 0
			self.ddl_count = 0
			self.last_update_time = None
			self.cached_insert_count = 0
			self.cached_update_count = 0
			self.cached_delete_count = 0
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemServerInfo(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
			self.description = None
			self.host = None
			self.port = None
			self.state = AemServerState.NOT_MONITORED
			self.message = None
			self.platform = AemPlatform.UNKNOWN
			self.version = None
			self.last_connection = None
			self.type = ServerType.REPLICATE
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemServerState[self.state]
			self.platform = AemPlatform[self.platform]
			self.type = ServerType[self.type]

class AemServer(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
			self.description = None
			self.host = None
			self.port = None
			self.username = None
			self.password = None
			self.monitored = True
			self.verify_server_certificate = False
			self.type = ServerType.REPLICATE
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.type = ServerType[self.type]

class AemGetEndpointListResp(object):
	def __init__(self, j = None):
		if not j:
			self.endpointList = []
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			for i, k in enumerate(self.endpointList):
				self.endpointList[i] = Endpoint(self.endpointList[i])

class AemGetServerListResp(object):
	def __init__(self, j = None):
		if not j:
			self.serverList = []
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			for i, k in enumerate(self.serverList):
				if self.serverList[i]['$type'] == 'ReplicateServerInfo':
					self.serverList[i] = ReplicateServerInfo(self.serverList[i])
					continue
				if self.serverList[i]['$type'] == 'ComposeServerInfo':
					self.serverList[i] = ComposeServerInfo(self.serverList[i])
					continue

class AemTableFullLoadInfo(object):
	def __init__(self, j = None):
		if not j:
			self.start_time = None
			self.end_time = None
			self.estimated_row_count = 0
			self.estimated_end_time = None
			self.transferred_row_count = 0
			self.transferred_volume_mb = 0
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemGetTableListResp(object):
	def __init__(self, j = None):
		if not j:
			self.tablelist = []
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			for i, k in enumerate(self.tablelist):
				self.tablelist[i] = AemTableInfo(self.tablelist[i])

class AemAuthorizationAcl(object):
	def __init__(self, j = None):
		if not j:
			self.admin_role = None
			self.designer_role = None
			self.operator_role = None
			self.viewer_role = None
			self.disable_inheritance = False
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.admin_role = AemRoleDef(self.admin_role)
			self.designer_role = AemRoleDef(self.designer_role)
			self.operator_role = AemRoleDef(self.operator_role)
			self.viewer_role = AemRoleDef(self.viewer_role)

class ApiLicense(object):
	def __init__(self, j = None):
		if not j:
			self.issue_date = None
			self.state = AemLicenseState.VALID_LICENSE
			self.expiration = None
			self.days_to_expiration = 0
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemLicenseState[self.state]

class Endpoint(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
			self.description = None
			self.role = EndpointRole.ALL
			self.type = None
			self.is_licensed = False
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.role = EndpointRole[self.role]

class AemGetChangeDataRetentionBarrierResp(object):
	def __init__(self, j = None):
		if not j:
			self.application = None
			self.retention_point = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemServerUtilization(object):
	def __init__(self, j = None):
		if not j:
			self.disk_usage_mb = 0
			self.memory_mb = 0
			self.attunity_cpu_percentage = 0
			self.machine_cpu_percentage = 0
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemRunTaskResp(object):
	def __init__(self, j = None):
		if not j:
			self.state = AemTaskState.NOT_EXIST
			self.error_message = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.state = AemTaskState[self.state]

class AemUserRef(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemTestEndpointResp(object):
	def __init__(self, j = None):
		if not j:
			self.status = AemEndpointState.UNKNOWN
			self.message = None
			self.detailed_message = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.status = AemEndpointState[self.status]

class Configuration(object):
	def __init__(self, j = None):
		if not j:
			self.host = None
			self.platform = AemPlatform.UNKNOWN
			self.port = None
			self.user_name = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			self.platform = AemPlatform[self.platform]

class AemGetServerDetailsResp(object):
	def __init__(self, j = None):
		if not j:
			self.server_details = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			if self.server_details['$type'] == 'ReplicateServerDetails':
				self.server_details = ReplicateServerDetails(self.server_details)
			elif self.server_details['$type'] == 'ComposeServerDetails':
				self.server_details = ComposeServerDetails(self.server_details)

class AemGroupRef(object):
	def __init__(self, j = None):
		if not j:
			self.name = None
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemTasksSummary(object):
	def __init__(self, j = None):
		if not j:
			self.total = 0
			self.running = 0
			self.stopped = 0
			self.recovering = 0
			self.error = 0
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)

class AemGetTaskListResp(object):
	def __init__(self, j = None):
		if not j:
			self.taskList = []
		else:
			self.__dict__ = AttUtil.attobject_from_json(j)
			for i, k in enumerate(self.taskList):
				self.taskList[i] = AemTaskInfo(self.taskList[i])

#child classes
class ReplicateServerInfo(AemServerInfo):
	def __init__(self, j = None):
		AemServerInfo.__init__(self, j)

class AemTaskInfoDetailed(AemTaskInfoDetailedBase):
	def __init__(self, j = None):
		AemTaskInfoDetailedBase.__init__(self, j)

class AemComposeServer(AemServer):
	def __init__(self, j = None):
		AemServer.__init__(self, j)

class AemReplicateServer(AemServer):
	def __init__(self, j = None):
		AemServer.__init__(self, j)

class ComposeServerInfo(AemServerInfo):
	def __init__(self, j = None):
		AemServerInfo.__init__(self, j)

class ReplicateServerDetails(AemServerDetails):
	def __init__(self, j = None):
		AemServerDetails.__init__(self, j)

class ComposeServerDetails(AemServerDetails):
	def __init__(self, j = None):
		AemServerDetails.__init__(self, j)

class AemComposeTaskInfoDetailed(AemTaskInfoDetailedBase):
	def __init__(self, j = None):
		AemTaskInfoDetailedBase.__init__(self, j)

class AemComposeDMTaskInfoDetailed(AemComposeTaskInfoDetailed):
	def __init__(self, j = None):
		AemComposeTaskInfoDetailed.__init__(self, j)

class AemComposeDLTaskInfoDetailed(AemComposeTaskInfoDetailed):
	def __init__(self, j = None):
		AemComposeTaskInfoDetailed.__init__(self, j)

class AemComposeDWTaskInfoDetailed(AemComposeTaskInfoDetailed):
	def __init__(self, j = None):
		AemComposeTaskInfoDetailed.__init__(self, j)


#endregion models

#region utils

class AuthenticationMethod(Enum):
	ACTIVE_DIRECTORY = 0
	SAML = 1

class AttUtil(object):
	@staticmethod
	def quote_param(url_param):
		if isinstance(url_param, Enum):
			url_param = url_param.name
		url_param = str(url_param).encode('utf-8')
		url_param = quote(url_param)
		return url_param
	# END function AttUtil.quote_param
	
	@staticmethod
	def attobject_from_json(obj):
		base_obj = obj
		if type(obj) is dict:
			return base_obj
		try:
			if isinstance(obj, base_string_type) or isinstance(obj, str) or isinstance(obj.decode('utf-8'), str):
				base_obj = json.loads(obj)
		except Exception as ex:
			print(ex)
		return base_obj
	# END function AttUtil.attobject_from_json
	
	@staticmethod
	def attobject_to_json(obj):
		if isinstance(obj, Enum):
			return obj.name
		elif (obj is None or (type(obj) is str) or (type(obj) is int) or (type(obj) is bool) or (type(obj) is bytes) or isinstance(obj, base_string_type) or (str(type(obj)) == "<type 'unicode'>")  ):
			return obj
		elif ( (type(obj) is list) or isinstance(obj, list) ):
			arr = []
			for item in obj:
				arr.append( AttUtil.attobject_to_json(item))
			return arr
		elif ( (type(obj) is dict) or (obj.__dict__ != None) ):
			# keep the object Type
			obj_type = obj.__class__.__name__
			sorted_dict = OrderedDict()
			# set $type as first
			sorted_dict['$type'] = obj_type
			for key in obj.__dict__:
				sorted_dict[key] = AttUtil.attobject_to_json(obj.__dict__[key])
			return sorted_dict
		else:
			return obj
	# END function AttUtil.attobject_to_json
	
	@staticmethod
	def validate_params(param_dict):
		for key in param_dict:
			item = param_dict[key]
			if not isinstance(item["value"], item["type"]):
				raise Exception('Param: "{0}" should be of type: "{1}", but was: "{2}"'.format(key, item["type"], type(item["value"]) ) )
	# END function AttUtil.validate_params
	
	@staticmethod
	def get_b64_user_pass(username, password):
		username_pass_tpl = str.encode('{0}:{1}'.format(username, password))
		return base64.b64encode(username_pass_tpl).decode('ascii')
	# END function AttUtil.get_b64_user_pass
# END class AttUtil

class AemClientException(Exception):
	def __init__(self, error_code, error_message):
		self.error_code = error_code
		self.message = error_message
		Exception.__init__(self, error_code, error_message)

class AttConnector(object):
	def __init__(self, b64_username_password, verify_certificate=True, authentication_method=AuthenticationMethod.ACTIVE_DIRECTORY):
		self.verify_certificate = verify_certificate
		if authentication_method == AuthenticationMethod.ACTIVE_DIRECTORY:
			self.headers = { 'Authorization' : 'Basic %s' %  b64_username_password }
		else:
			self.headers = dict()
		if verify_certificate:
			ssl._create_default_https_context = ssl.create_default_context
		else:
			ssl._create_default_https_context = ssl._create_unverified_context
	
	def att_request(self, method, url, payload=None, get_raw_error=False, content_type='application/json'):
		req_headers = {}
		for key in self.headers:
			req_headers[key] = self.headers[key]
		req_headers[HEADERS_CONTENT_TYPE] = content_type
		if payload:
			payload = payload.encode('utf-8')
			req_headers[HEADERS_CONTENT_LENGTH] = str(len(payload))
		elif HEADERS_CONTENT_LENGTH in req_headers:
			del req_headers[HEADERS_CONTENT_LENGTH]
		att_response = {}
		request_pyx = Request(url, data=payload, headers=req_headers)
		request_pyx.get_method = lambda: method
		try:
			att_response = urlopen(request_pyx)
		except HTTPError as ex:
			if get_raw_error:
				att_response = ex
			else:
				# TODO: G.G. - remove read, and adjust calls and errors
				att_response = ex.read()
		except URLError as ex:
			att_response = ex
		except Exception as ex:
			att_response = ex
		return att_response
	# end of att_request
	def save_headers(self, response):
		headers_dict = {}
		try:
			resp_info = response.info()
			for key in resp_info:
				if key != HEADERS_CONTENT_LENGTH:
					headers_dict[key] = response.headers[key]
		except Exception as ex:
			print(ex)
		self.headers = headers_dict
	# end of save_headers
# END of class AttConnector

#endregion utils

#region infrastructure

class AttClient(object):
	def __init__(self, b64_username_password, url="", verify_certificate=True, authentication_method=AuthenticationMethod.ACTIVE_DIRECTORY):
		if 'https' not in url:
			raise Exception('The Aem access URL must start with "https".')
		if not isinstance(authentication_method, AuthenticationMethod):
			raise Exception('authentication_method must be of type AuthenticationMethod')
		self.url = url
		self.attconnector = AttConnector(b64_username_password, verify_certificate, authentication_method)
		login_url = '{0}/api/v1/login'.format(self.url)
		if authentication_method == AuthenticationMethod.ACTIVE_DIRECTORY:
			saml_message = None
		else:
			saml_message = b64_username_password
		response = self.attconnector.att_request(method='POST', url=login_url, payload=saml_message, get_raw_error=True, content_type='application/x-www-form-urlencoded')
		if hasattr(response, 'code') and response.code == 200:
			self.attconnector.save_headers(response)
		else:
			self.attconnector = None
			if hasattr(response, 'reason') and response.reason:
				raise Exception("Http Error: {0}".format(response.reason))
			else:
				resp_json = json.loads(response)
				raise AemClientException(resp_json['error_code'], resp_json['error_message'])
	# END function __init__
	
	def do_web_request(self, resp_class=None, address=None, http_method='GET', req = None, stream_req = False):
		full_url = '{0}/{1}'.format(self.url, address)
		payload = None
		if req:
			if stream_req:
				payload = req
			else:
				att_json = AttUtil.attobject_to_json(req)
				payload = json.dumps( att_json, sort_keys=True )
		response_t = self.attconnector.att_request(method=http_method, url=full_url, payload=payload)
		response_text = None
		try:
			response_text = response_t.read()
		except Exception as ex:
			if hasattr(response_t, 'reason') and response_t.reason:
				raise Exception('Http Error: {0}'.format(response_t.reason))
			else:
				response_t = json.loads(response_t)
		if 'error_code' in response_t or 'status_code' in response_t:
			raise AemClientException(response_t['error_code'], response_t['error_message'])
		if resp_class:
			return resp_class(response_text)
		return response_text
	# END function do_web_request

#endregion infrastructure


class AemClient(AttClient):
	def __init__(self, b64_username_password, machine_name, port=443, url="https://{0}/attunityenterprisemanager", verify_certificate=True, authentication_method=AuthenticationMethod.ACTIVE_DIRECTORY):
		if port != 443:
			machine_name = '{0}:{1}'.format(machine_name, port)
		if url.find('{0}'):
			url = url.format(machine_name)
		self.attclient = AttClient(b64_username_password, url, verify_certificate, authentication_method)
	def delete_endpoint(self, server, endpoint):
		"""
		parameters:
			server - string
			endpoint - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'endpoint':{'value':endpoint,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/endpoints/" + AttUtil.quote_param(endpoint) + "?action=delete"
		self.attclient.do_web_request(None, address, 'POST', None)
	
	def delete_old_change_data(self, payload, server, task):
		"""
		request payload: AemDeleteOldChangeDataReq
		parameters:
			server - string
			task - string
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':AemDeleteOldChangeDataReq }, 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=delete_old_change_data"
		self.attclient.do_web_request(None, address, 'POST', payload)
	
	def delete_server_acl(self, server):
		"""
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "?action=acl"
		self.attclient.do_web_request(None, address, 'DELETE', None)
	
	def delete_server(self, server):
		"""
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/def"
		self.attclient.do_web_request(None, address, 'DELETE', None)
	
	def delete_task(self, server, task, deletetasklogs = False):
		"""
		parameters:
			server - string
			task - string
			deletetasklogs - bool
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type }, 'deletetasklogs':{'value':deletetasklogs,'type':bool } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=delete&deletetasklogs=" + AttUtil.quote_param(deletetasklogs) + ""
		self.attclient.do_web_request(None, address, 'POST', None)
	
	def export_all(self, server):
		"""
		response payload: STREAM
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "?action=export"
		resp = self.attclient.do_web_request(None, address, 'GET', None)
		return resp
	
	def export_audit_trail(self, start_timestamp = None, end_timestamp = None):
		"""
		response payload: STREAM
		parameters:
			start_timestamp - string
			end_timestamp - string
		"""
		AttUtil.validate_params({ 'start_timestamp':{'value':start_timestamp,'type':base_string_type }, 'end_timestamp':{'value':end_timestamp,'type':base_string_type } })
		address = "api/v1/security/audit_trail?start_timestamp=" + AttUtil.quote_param(start_timestamp) + "&end_timestamp=" + AttUtil.quote_param(end_timestamp) + ""
		resp = self.attclient.do_web_request(None, address, 'GET', None)
		return resp
	
	def export_task(self, server, task, withendpoints = False):
		"""
		response payload: STREAM
		parameters:
			server - string
			task - string
			withendpoints - bool
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type }, 'withendpoints':{'value':withendpoints,'type':bool } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=export&withendpoints=" + AttUtil.quote_param(withendpoints) + ""
		resp = self.attclient.do_web_request(None, address, 'GET', None)
		return resp
	
	def get_change_data_retention_barrier(self, server, task):
		"""
		response payload: AemGetChangeDataRetentionBarrierResp
		parameters:
			server - string
			task - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=get_change_data_retention_barrier"
		resp = self.attclient.do_web_request(AemGetChangeDataRetentionBarrierResp, address, 'GET', None)
		return resp
	
	def get_endpoint_list(self, server):
		"""
		response payload: AemGetEndpointListResp
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/endpoints"
		resp = self.attclient.do_web_request(AemGetEndpointListResp, address, 'GET', None)
		return resp
	
	def get_server_acl(self, server):
		"""
		response payload: AemAuthorizationAcl
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "?action=acl"
		resp = self.attclient.do_web_request(AemAuthorizationAcl, address, 'GET', None)
		return resp
	
	def get_server_details(self, server):
		"""
		response payload: AemGetServerDetailsResp
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + ""
		resp = self.attclient.do_web_request(AemGetServerDetailsResp, address, 'GET', None)
		return resp
	
	def get_server_list(self, ):
		"""
		response payload: AemGetServerListResp
		parameters:
		"""
		address = "api/v1/servers"
		resp = self.attclient.do_web_request(AemGetServerListResp, address, 'GET', None)
		return resp
	
	def get_server(self, server):
		"""
		response payload: AemServer
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/def"
		resp = self.attclient.do_web_request(AemServer, address, 'GET', None)
		return resp
	
	def get_table_list(self, server, task, schema = None, table = None, includequeued = False, includeloading = False, includecompleted = False, includechangeprocessing = False, includeerror = False):
		"""
		response payload: AemGetTableListResp
		parameters:
			server - string
			task - string
			schema - string
			table - string
			includequeued - bool
			includeloading - bool
			includecompleted - bool
			includechangeprocessing - bool
			includeerror - bool
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type }, 'schema':{'value':schema,'type':base_string_type }, 'table':{'value':table,'type':base_string_type }, 'includequeued':{'value':includequeued,'type':bool }, 'includeloading':{'value':includeloading,'type':bool }, 'includecompleted':{'value':includecompleted,'type':bool }, 'includechangeprocessing':{'value':includechangeprocessing,'type':bool }, 'includeerror':{'value':includeerror,'type':bool } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "/tables?schema=" + AttUtil.quote_param(schema) + "&table=" + AttUtil.quote_param(table) + "&includequeued=" + AttUtil.quote_param(includequeued) + "&includeloading=" + AttUtil.quote_param(includeloading) + "&includecompleted=" + AttUtil.quote_param(includecompleted) + "&includechangeprocessing=" + AttUtil.quote_param(includechangeprocessing) + "&includeerror=" + AttUtil.quote_param(includeerror) + ""
		resp = self.attclient.do_web_request(AemGetTableListResp, address, 'GET', None)
		return resp
	
	def get_table_statuses(self, server, task, schema = None, table = None, includequeued = False, includeloading = False, includecompleted = False, includechangeprocessing = False, includeerror = False):
		"""
		response payload: AemGetTableStatusesResp
		parameters:
			server - string
			task - string
			schema - string
			table - string
			includequeued - bool
			includeloading - bool
			includecompleted - bool
			includechangeprocessing - bool
			includeerror - bool
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type }, 'schema':{'value':schema,'type':base_string_type }, 'table':{'value':table,'type':base_string_type }, 'includequeued':{'value':includequeued,'type':bool }, 'includeloading':{'value':includeloading,'type':bool }, 'includecompleted':{'value':includecompleted,'type':bool }, 'includechangeprocessing':{'value':includechangeprocessing,'type':bool }, 'includeerror':{'value':includeerror,'type':bool } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "/tables?action=getstatus&schema=" + AttUtil.quote_param(schema) + "&table=" + AttUtil.quote_param(table) + "&includequeued=" + AttUtil.quote_param(includequeued) + "&includeloading=" + AttUtil.quote_param(includeloading) + "&includecompleted=" + AttUtil.quote_param(includecompleted) + "&includechangeprocessing=" + AttUtil.quote_param(includechangeprocessing) + "&includeerror=" + AttUtil.quote_param(includeerror) + ""
		resp = self.attclient.do_web_request(AemGetTableStatusesResp, address, 'GET', None)
		return resp
	
	def get_task_details(self, server, task):
		"""
		response payload: AemTaskInfoDetailedBase
		parameters:
			server - string
			task - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + ""
		resp = self.attclient.do_web_request(AemTaskInfoDetailedBase, address, 'GET', None)
		return resp
	
	def get_task_list(self, server):
		"""
		response payload: AemGetTaskListResp
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks"
		resp = self.attclient.do_web_request(AemGetTaskListResp, address, 'GET', None)
		return resp
	
	def import_all(self, payload, server):
		"""
		request payload: STREAM
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':base_string_type }, 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "?action=import"
		self.attclient.do_web_request(None, address, 'POST', payload, True)
	
	def import_task(self, payload, server, task):
		"""
		request payload: STREAM
		parameters:
			server - string
			task - string
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':base_string_type }, 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=import"
		self.attclient.do_web_request(None, address, 'POST', payload, True)
	
	def put_server_acl(self, payload, server):
		"""
		request payload: AemAuthorizationAcl
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':AemAuthorizationAcl }, 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "?action=acl"
		self.attclient.do_web_request(None, address, 'PUT', payload)
	
	def put_server_license(self, payload, server):
		"""
		request payload: STREAM
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':base_string_type }, 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/license/def"
		self.attclient.do_web_request(None, address, 'PUT', payload, True)
	
	def put_server(self, payload, server):
		"""
		request payload: AemServer
		parameters:
			server - string
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':AemServer }, 'server':{'value':server,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/def"
		self.attclient.do_web_request(None, address, 'PUT', payload)
	
	def reconfigure_endpoint_no_wait(self, server, endpoint, configuration = None, recycle = True):
		"""
		parameters:
			server - string
			endpoint - string
			configuration - string
			recycle - bool
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'endpoint':{'value':endpoint,'type':base_string_type }, 'configuration':{'value':configuration,'type':base_string_type }, 'recycle':{'value':recycle,'type':bool } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/endpoints/" + AttUtil.quote_param(endpoint) + "?action=reconfigure&configuration=" + AttUtil.quote_param(configuration) + "&recycle=" + AttUtil.quote_param(recycle) + ""
		self.attclient.do_web_request(None, address, 'PUT', None)
	
	def reload_table(self, server, task, schema = None, table = None):
		"""
		parameters:
			server - string
			task - string
			schema - string
			table - string
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type }, 'schema':{'value':schema,'type':base_string_type }, 'table':{'value':table,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "/tables?action=reload&schema=" + AttUtil.quote_param(schema) + "&table=" + AttUtil.quote_param(table) + ""
		self.attclient.do_web_request(None, address, 'POST', None)
	
	def run_task(self, payload, server, task, option = AemRunTaskOptions.RESUME_PROCESSING, timeout = 30):
		"""
		request payload: AemRunTaskReq
		response payload: AemRunTaskResp
		parameters:
			server - string
			task - string
			option - AemRunTaskOptions
			timeout - int32
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':AemRunTaskReq }, 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type }, 'option':{'value':option,'type':AemRunTaskOptions }, 'timeout':{'value':timeout,'type':int } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=run&option=" + AttUtil.quote_param(option) + "&timeout=" + AttUtil.quote_param(timeout) + ""
		resp = self.attclient.do_web_request(AemRunTaskResp, address, 'POST', payload)
		return resp
	
	def set_change_data_retention_barrier(self, payload, server, task):
		"""
		request payload: AemSetChangeDataRetentionBarrierReq
		parameters:
			server - string
			task - string
		"""
		AttUtil.validate_params({ 'payload':{'value':payload,'type':AemSetChangeDataRetentionBarrierReq }, 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=set_change_data_retention_barrier"
		self.attclient.do_web_request(None, address, 'PUT', payload)
	
	def stop_task(self, server, task, timeout = 30):
		"""
		response payload: AemStopTaskResp
		parameters:
			server - string
			task - string
			timeout - int32
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'task':{'value':task,'type':base_string_type }, 'timeout':{'value':timeout,'type':int } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/tasks/" + AttUtil.quote_param(task) + "?action=stop&timeout=" + AttUtil.quote_param(timeout) + ""
		resp = self.attclient.do_web_request(AemStopTaskResp, address, 'POST', None)
		return resp
	
	def test_endpoint(self, server, endpoint, timeout = 60):
		"""
		response payload: AemTestEndpointResp
		parameters:
			server - string
			endpoint - string
			timeout - int32
		"""
		AttUtil.validate_params({ 'server':{'value':server,'type':base_string_type }, 'endpoint':{'value':endpoint,'type':base_string_type }, 'timeout':{'value':timeout,'type':int } })
		address = "api/v1/servers/" + AttUtil.quote_param(server) + "/endpoints/" + AttUtil.quote_param(endpoint) + "?action=test&timeout=" + AttUtil.quote_param(timeout) + ""
		resp = self.attclient.do_web_request(AemTestEndpointResp, address, 'GET', None)
		return resp
	
