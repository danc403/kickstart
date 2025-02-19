#!/usr/bin/env python3
""" Simple flask server to serve all .cfg files in the current directory.
I use it when i don't have a reachable server on the local network for kickstart installs.
By default it binds to all interfaces on port 5000
If you visit 'localhost' in your browser it will tell you the ip and port
along with a list of cfg files in the directory 
To exit use ctrl + c
"""

from flask import Flask, send_from_directory, render_template_string
import os
import socket

app = Flask(__name__)

# Directory to serve files from
STATIC_DIR = '.'

def get_instructions(ip,port):

    return f"""<br><h2>Instructions:</h2>
Boot from the Rocky Linux 9 minimal ISO image.<br>
At the boot prompt, press Tab to edit the boot options.<br>
Modify the boot command by adding inst.ks=http://your_web_server/ks.cfg to the end.<br>
For example, if your web server's address is {ip}:{port} and your kickstart file is named ks.cfg, the boot command would look like this:<br>
<code>vmlinuz inst.repo=http://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/ inst.ks=http://{ip}:{port}/ks.cfg quiet</code>
<br>
Press Enter to start the installation.<br>     
    """

def get_listening_address(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for this purpose
        s.connect(("8.8.8.8", 80))  # Connect to a known external host
        ip_address = s.getsockname()[0] #get local ip
        s.close()
        return ip_address, port
    except Exception as e:
        print(f"Error getting listening address: {e}")
        return "127.0.0.1", port  # Fallback to localhost only if absolutely necessary

@app.route('/')
def index():
    # List all .cfg files in the static directory
    cfg_files = [f for f in os.listdir(STATIC_DIR) if f.endswith('.cfg')]

    ip_address, port = get_listening_address(5000) #get ip and port
    instructions = get_instructions(ip_address, port)

    # Generate a simple HTML index
    html = f'''
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Kickstart Files</title>
    </head>
    <body>
        <h1>A quick local server for your kickstart files.</h1>
        <p>Server Address: {ip_address}:{port}</p>  
        <h2>Kickstart Files</h2>
        <ul>
    '''
    for file in cfg_files:
        html += f'<li><a href="/{STATIC_DIR}/{file}">{file}</a></li>'
    html += f'''
        </ul>
        <p>{instructions}</p>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route(f'/{STATIC_DIR}/<path:filename>')
def serve_cfg(filename):
    # Serve .cfg files from the static directory
    if filename.endswith('.cfg'):
        return send_from_directory(STATIC_DIR, filename)
    else:
        return "File not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
