import json
import os
import requests
import tempfile
import time

class Live_Token:
    @staticmethod
    def fetch_api_token(username, password):
        while True:
            try:
                api_url = 'https://identity.api.dat.com/access/v1/token/organization'
                payload = {
                    'username': username,
                    'password': password
                }

                headers = {
                    'Content-Type': 'application/json'
                }
                response = requests.post(api_url, json=payload, headers=headers)
                response.raise_for_status()
                response_data = response.json()
                if 'accessToken' in response_data:
                    access_token = response_data['accessToken']
                    return access_token
            except requests.exceptions.RequestException as e:
                print('Error:', e)
                # Wait for 3 seconds before retrying
                time.sleep(3)

    @staticmethod
    def fetch_user_access_token(url, headers, payload):
        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            response_data = response.json()
            if 'accessToken' in response_data:
                return response_data['accessToken']
            else:
                print('User Access Token Response Data:', response_data)
                return None
        except requests.exceptions.RequestException as e:
            print('Error:', e)
            return None

    @staticmethod
    def save_token_to_file(username, token):
        # Create a temporary file to save the token
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json', prefix=f'{username}_', mode='w') as temp_file:
                file_path = temp_file.name
                json.dump({"access_token": token}, temp_file)
                print(f'{username} user access token saved to {file_path}')
            return file_path  # Return the path to the temporary file
        except IOError as e:
            print(f"File I/O Error: {e}")
            return None

    @staticmethod
    def get_token_from_file(file_path):
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as file:
                    return json.load(file)
            except IOError as e:
                print(f"File I/O Error: {e}")
                return {"error": "Error reading file"}
            except json.JSONDecodeError:
                return {"error": "Error decoding JSON from file"}
        return {"error": "File not found"}
