import json
import os
import pandas as pd
import requests
import urllib3

urllib3.disable_warnings()

auth_server = "https://ws-api.onehub.com/oauth/"
redirect_uri = "http://localhost"

def get_auth_url(client_id):
	print(f"https://ws-api.onehub.com/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=http://localhost")

def store_access_token(url, client_id, client_secret):
	if "=" not in url:
		raise Exception("InvalidURLFormatError: The url should follow the format http://localhost/?code=<AUTHORIZATION CODE HERE>.")
	auth_code = url.split("=")[-1]
	r = requests.post(f"https://ws-api.onehub.com/oauth/authorize?grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={auth_code}&redirect_uri=http://localhost")
	if r.status_code != 200:
		raise Exception(f"BadRequestError: The inputs you provided returned a {r.status_code} status code. Please review your inputs or restart the process by first regenerating your auth URL.")
	access_token = json.loads(str(r.text))
	dir_path = os.path.dirname(os.path.realpath(__file__)).replace("\\", "/")
	with open(f"{dir_path}/conf.json", "w") as f:
		json.dump(access_token, f)

def get_access_token():
	try:
		dir_path = os.path.dirname(os.path.realpath(__file__)).replace("\\", "/")
		with open(f"{dir_path}/conf.json") as f:
			d = json.load(f)
		return d["access_token"]
	except:
		raise Exception("MissingAccessToken: Generate an access token using the store_access_token method. More information can be found here: https://github.com/sorrek/sorrek-dataroom/sorrek-dataroom/README.rst")

def return_output(r):
	if r.status_code in [200, 201, 204]:
		try:
			return json.loads(r.text)
		except:
			return
	elif r.status_code == 401:
		raise Exception("InvalidCredentialsError: Generate a new access token using the store_access_token method. More information can be found here: https://github.com/sorrek/sorrek-dataroom/sorrek-dataroom/README.rst")
	elif r.status_code == 422:
		raise Exception("BadRequestError: Your file object was empty or there was an error in the message body.")
	else:
		raise Exception(f"BadRequestError: The inputs you provided returned a {r.status_code} status code. Please review your inputs or restart the process by first regenerating your auth URL.")

def upload_csv_file(folder_id, upload_file_path):
	if not upload_file_path.endswith(".csv"):
		raise Exception("InvalidFileTypeError: The upload file must be in a .csv format.")
	access_token = get_access_token()
	api_call_headers = {"Authorization": "Bearer " + access_token, "Connection" : "keep-alive"}
	files = {'file': (upload_file_path, open(upload_file_path, 'rb'), 'text/csv', {'Expires': '0'})}
	r = requests.post(f"https://ws-api.onehub.com/folders/{folder_id}/files", headers=api_call_headers, files=files, verify=False)
	return return_output(r)
 
def download_csv_to_df(file_id):
	access_token = get_access_token()
	api_call_headers = {"Authorization": "Bearer " + access_token}
	r = requests.get(f"https://ws-api.onehub.com/download/{file_id}", headers=api_call_headers, verify=False)
	if r.status_code != 200:
		return return_output(r)
	dir_path = os.path.dirname(os.path.realpath(__file__)).replace("\\", "/")
	with open(f"{dir_path}/tmp.csv", "w", encoding="utf-8") as out:
		out.write(r.text)
	df = pd.read_csv(f"{dir_path}/tmp.csv")
	return df

def delete_file(file_id):
	access_token = get_access_token()
	api_call_headers = {"Authorization": "Bearer " + access_token}
	r = requests.delete(f"https://ws-api.onehub.com/files/{file_id}", headers=api_call_headers, verify=False)
	return return_output(r)

def get_file_metadata(file_id):
	access_token = get_access_token()
	api_call_headers = {"Authorization": "Bearer " + access_token}
	r = requests.get(f"https://ws-api.onehub.com/files/{file_id}", headers=api_call_headers, verify=False)
	return return_output(r)

def rename_file(file_id, new_file_name):
	access_token = get_access_token()
	if "." not in new_file_name:
		meta = get_file_metadata(file_id)
		file_name = meta["file"]["filename"]
		if "." in file_name:	
			file_extension = file_name.split(".")[-1]
			new_file_name = f"{new_file_name}.{file_extension}"
	api_call_headers = {"Authorization": "Bearer " + access_token}
	r = requests.put(f"https://ws-api.onehub.com/files/{file_id}", headers=api_call_headers, json={"filename" : new_file_name}, verify=False)
	return return_output(r)

def get_folder_contents(folder_id, offset=0):
	access_token = get_access_token()
	api_call_headers = {"Authorization": "Bearer " + access_token}
	r = requests.get(f"https://ws-api.onehub.com/folders/{folder_id}?offset={offset}", headers=api_call_headers, verify=False)
	return return_output(r)
