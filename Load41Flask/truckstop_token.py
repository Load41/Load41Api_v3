import requests
import base64
import json
import os
import tempfile
from flask import Flask

app = Flask(__name__)

# Define the API URL
TOKEN_URL = "https://api.truckstop.com/auth/token?scope=truckstop"

# Global variables
ACCESS_TOKEN = None
REFRESH_TOKEN = None

class Truckstop_Token:

    @staticmethod
    def obtain_access_tokens(client_id, client_secret, username, password):
        global ACCESS_TOKEN, REFRESH_TOKEN
        client_credentials = f"{client_id}:{client_secret}"
        client_credentials_base64 = base64.b64encode(client_credentials.encode()).decode()
        data = {"grant_type": "password", "username": username, "password": password}
        headers = {
            "Authorization": f"Basic {client_credentials_base64}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = requests.post(TOKEN_URL, data=data, headers=headers)
            response.raise_for_status()
            token_data = response.json()
            ACCESS_TOKEN = token_data.get("access_token")
            REFRESH_TOKEN = token_data.get("refresh_token")
            print(token_data.get("access_token"))
            print(token_data.get("refresh_token"))
            return ACCESS_TOKEN
        except requests.exceptions.RequestException as e:
            print(f"Login Error: {e}\n")
            return None

    @staticmethod
    def refresh_and_save_access_token():
        # Implementation for refreshing the token if needed
        pass

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