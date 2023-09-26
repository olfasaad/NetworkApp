from netmiko import ConnectHandler
import os
from textfsm import TextFSM

def connx(device_type,ip,username,password,port):

	device = {
		'device_type': device_type,
		'ip': ip,
		'username': username,
		'password':  password,
		'port': port
		}

	return ConnectHandler(**device)




def get_interfaces(device):
	output_interfaces = device.send_command('show arp')
	current_dir = os.getcwd()
	template_file = open(current_dir +"/controller/show_arp.template", "r")
	template = TextFSM(template_file)
	parsed_interfaces = template.ParseText(output_interfaces)
   
	interface_list = []
	for interface_data in parsed_interfaces:
		resultDict = {}
		resultDict["ADDRESS"] = interface_data[0]
		resultDict["AGE"] = interface_data[1]
		resultDict["MAC"] = interface_data[2]
		resultDict["TYPE"] = interface_data[3]
		resultDict["INTERFACE"] = interface_data[4]
		

		interface_list.append(resultDict)
		

	return interface_list