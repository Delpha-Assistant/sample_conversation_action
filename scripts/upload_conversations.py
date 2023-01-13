from aifc import Error
import base64
import shutil
import os
import requests
import sys, getopt
import json

def main(inputfile, version):
    #Retrieve all env beforehand
    try:
        
        refresh_token = os.environ['REFRESH_TOKEN']
        consumerSecret = os.environ['CONSUMER_SECRET']
        consumerKey = os.environ['CONSUMER_KEY']
        endpoint = os.environ['SALESFORCE_ENDPOINT']
    except NameError as e:
        print(e)
        return
    
    
    upload_conv(inputfile, consumerKey, consumerSecret, refresh_token, endpoint)
    
def upload_conv(inputfile, consumerKey, consumerSecret, refresh_token, endpoint):
	# Decode zip file to base64_string
	with open(inputfile, "rb") as f:
		bytes = f.read()
		encoded = base64.b64encode(bytes)
		base64_string = encoded.decode('utf-8')

	# POST base64_string to targetted org 
	headers = {'Authorization': 'Bearer ' + salesforceConnect(True, consumerKey, consumerSecret, refresh_token)['access_token']}
	data = {'base64' : base64_string}
	response = requests.post(endpoint, json=data, headers=headers)
	print(response.json())

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

if __name__ == "__main__":
	main(sys.argv[1], sys.argv[2])
