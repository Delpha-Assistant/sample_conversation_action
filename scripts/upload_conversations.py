from aifc import Error
import base64
import shutil
import os
import requests
import sys, getopt
import json

def main(argv):
	inputfile = ''
	refresh_token=''
	consumerSecret=''
	consumerKey=''
	compressonly=False
	version=''
	helpMsg='upload_conv.py -i <inputfile> -r <refresh_token> -s <consumer_secret> -k <consumer_key> -v <version> -c [Optional. Compress Only]'
	try:
		opts, args = getopt.getopt(argv,"hi:v:r:s:k:c",["help","ifile=","version=","refresh_token=","consumer_secret=","consumer_key=","compress"])
	except getopt.GetoptError as err:
		print(err)
		print(helpMsg)
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print('upload_conv.py -i <inputfile>')
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
		elif opt in ("-r", "--refresh_token"):
			refresh_token = arg
		elif opt in ("-s", "--consumer_secret"):
			consumerSecret = arg
		elif opt in ("-k", "--consumer_key"):
			consumerKey = arg
		elif opt in ("-c", "--compress_only"):
			compressonly = True
		elif opt in ("-v", "--version"):
			version = arg
	if version == '' or not os.path.isdir(inputfile):
		print(helpMsg)
	else:
		setVersion(version,inputfile)
	if compressonly and inputfile != '':
		zip_compression_tree('./{}'.format(inputfile),inputfile)
	elif inputfile == '' or refresh_token == '' or consumerKey == '' or consumerSecret=='':
		print(helpMsg)
		sys.exit(2)
	else:
		if os.path.isdir(inputfile):
			zipfile = '{}.zip'.format(inputfile)
			zip_compression_tree('./{}'.format(inputfile),inputfile)
			upload_conv(zipfile,consumerKey,consumerSecret,refresh_token)
		else:
			upload_conv(inputfile,consumerKey,consumerSecret,refresh_token)
	sys.exit()

def upload_conv(inputfile,consumerKey,consumerSecret,refresh_token):
	#decode zip file to base64_string
	with open(inputfile, "rb") as f:
		bytes = f.read()
		encoded = base64.b64encode(bytes)
		base64_string = encoded.decode('utf-8')

	#POST base64_string to targetted org 
	headers = {'Authorization': 'Bearer ' + salesforceConnect(True,consumerKey,consumerSecret,refresh_token)['access_token']}
	data = {'base64' : base64_string}
	endpoint = os.environ.get('SALESFORCE_ENDPOINT')
	response = requests.post(endpoint, json=data, headers=headers)
	print(response.json())

def setVersion(version, conversation_folder):
	conversationJsonPath = '{}/Conversation.json'.format(conversation_folder)
	if os.path.exists(conversationJsonPath):
		with open(conversationJsonPath,'r') as conversationFile:
			json_data = json.load(conversationFile)	
			conversationFile.close()
			json_data[0]['delpha__Customer_Version_ID__c'] = version
			with open(conversationJsonPath,'w+') as conversationFile:
				json.dump(json_data,conversationFile, indent=4)	
				conversationFile.close()	

def salesforceConnect(isSandbox,consumerKey,consumerSecret,refresh_token):
	DOMAIN = 'test' if isSandbox else 'login'
	r = requests.post('https://{}.salesforce.com/services/oauth2/token'.format(DOMAIN), data = {
    'grant_type': 'refresh_token',
    'client_id': consumerKey,
    'client_secret': consumerSecret,
    'refresh_token': refresh_token
	})

	print('Status salesforce connection:', r.status_code)
	result = r.json()
	return result

def zip_compression_tree(input_dir, output_filename):
	shutil.make_archive(output_filename,'zip',input_dir)

if __name__ == "__main__":
	main(sys.argv[1:])
