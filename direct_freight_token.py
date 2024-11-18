import requests
import json
import os  # To handle environment variables
from datetime import datetime
import tempfile

class Direct_Token:
    @staticmethod
    def obtain_access_tokens(username, password,api_token):
        # Call your function to obtain tokens
        # Example implementation (Replace with actual token fetching logic)
        TOKEN_URL = 'https://api.directfreight.com/v1/end_user_authentications'
        data = {"login": username, "realm": "email", "secret": password}
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'api-token': api_token
        }
        try:
            response = requests.post(TOKEN_URL, json=data, headers=headers)
            response.raise_for_status()
            token_data = response.json()
            ACCESS_TOKEN = token_data.get("end-user-token")
            return ACCESS_TOKEN
        except requests.exceptions.RequestException as e:
            print(f"Request Error: {e}")
        except json.JSONDecodeError:
            print("Error decoding JSON response.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

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
