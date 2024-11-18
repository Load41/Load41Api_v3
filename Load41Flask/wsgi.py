# from waitress import serve
# from app import app

# if __name__ == "__main__":
#     serve(app, host='0.0.0.0', port=8000, timeout=120)

from waitress import serve
from app import socketio_app  # Import the combined app

if __name__ == "__main__":
    serve(socketio_app, host='0.0.0.0', port=6969)

