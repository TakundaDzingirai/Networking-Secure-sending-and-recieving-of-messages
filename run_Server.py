from waitress import serve
import Server  # Replace 'server' with the actual name of your Python file

serve(Server.app, host='0.0.0.0', port=5000)
