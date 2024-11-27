import socket
import threading
import os
import sqlite3
import hashlib
import json
from datetime import datetime

HEADER_SIZE = 10  # 10 bytes for header

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    # Create messages table
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            channel TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Create channels table
    c.execute('''
        CREATE TABLE IF NOT EXISTS channels (
            name TEXT PRIMARY KEY,
            created_by TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

def load_channels():
    global channels
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT name FROM channels')
    result = c.fetchall()
    conn.close()
    for (channel_name,) in result:
        channels[channel_name] = set()
    # Ensure 'General' channel exists
    if 'General' not in channels:
        channels['General'] = set()
        # Insert 'General' channel into the database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO channels (name, created_by) VALUES (?, ?)', ('General', 'server'))
        conn.commit()
        conn.close()

init_db()
channels = {}  # {channel_name: set of usernames}
load_channels()
channels_lock = threading.Lock()

clients = {}  # {username: {'socket': socket, 'role': role, 'channel': channel}}
clients_lock = threading.Lock()  # Lock for clients dictionary
addresses = {}  # {socket: address}
muted_users = set()
shared_files = []  # List of shared files

def send_data(sock, data_type, data):
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    length = len(data_bytes)
    header = f"{length:<8}{data_type:<2}".encode('utf-8')
    try:
        sock.sendall(header + data_bytes)
    except Exception as e:
        print(f"Error sending data to client: {e}")

def recv_data(sock):
    try:
        # Receive header
        header = b''
        while len(header) < HEADER_SIZE:
            part = sock.recv(HEADER_SIZE - len(header))
            if not part:
                return None, None
            header += part
        length = int(header[:8].strip())
        data_type = header[8:10].decode('utf-8').strip()
        # Receive data
        data = b''
        while len(data) < length:
            part = sock.recv(length - len(data))
            if not part:
                break
            data += part
        return data_type, data
    except Exception as e:
        print(f"Error receiving data from client: {e}")
        return None, None

def handle_client(client_socket, client_address):
    print(f"[NEW CONNECTION] {client_address} connected.")
    addresses[client_socket] = client_address

    user = authenticate(client_socket)
    if user:
        user_role = get_user_role(user)
        with clients_lock:
            clients[user] = {'socket': client_socket, 'role': user_role, 'channel': 'General'}
        with channels_lock:
            channels['General'].add(user)
        broadcast_user_list()
        send_system_message(f"{user} has joined the chat.", exclude=[user], channel='General')
        send_channel_list(client_socket)

        try:
            # Send recent messages from 'General' channel
            recent_messages = get_recent_messages('General')
            for msg in recent_messages:
                msg_data = {'sender': msg[0], 'message': msg[1], 'timestamp': msg[2]}
                send_data(client_socket, 'ms', json.dumps(msg_data))
            while True:
                data_type, data = recv_data(client_socket)
                if data_type:
                    if data_type == 'ms':  # Message
                        msg_data = json.loads(data.decode('utf-8'))
                        handle_message(msg_data, user)
                    elif data_type == 'cm':  # Command
                        msg_data = json.loads(data.decode('utf-8'))
                        handle_command(msg_data, user)
                    elif data_type == 'fu':  # File Upload
                        msg_data = json.loads(data.decode('utf-8'))
                        handle_file_upload(client_socket, msg_data, user)
                    elif data_type == 'fr':  # File Request
                        msg_data = json.loads(data.decode('utf-8'))
                        handle_file_request(client_socket, msg_data, user)
                else:
                    break
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            # Clean up on disconnect
            with clients_lock:
                current_channel = clients[user]['channel']
                with channels_lock:
                    if user in channels.get(current_channel, set()):
                        channels[current_channel].remove(user)
                        if not channels[current_channel]:
                            del channels[current_channel]
                del clients[user]
            del addresses[client_socket]
            broadcast_user_list()
            broadcast_channel_list()
            send_system_message(f"{user} has left the chat.", channel=current_channel)
            print(f"[DISCONNECT] {user} disconnected.")
            client_socket.close()
    else:
        client_socket.close()

def authenticate(client_socket):
    while True:
        data_type, data = recv_data(client_socket)
        if data_type == 'au':
            credentials = json.loads(data.decode('utf-8'))
            action = credentials['action']
            username = credentials['username']
            password = credentials['password']
            role = credentials.get('role', 'student')

            if action == 'register':
                if register_user(username, password, role):
                    response = {'status': 'ok', 'action': 'register', 'role': role}
                    send_data(client_socket, 'au', json.dumps(response))
                    print(f"[REGISTER] New user registered: {username} ({role})")
                    return username
                else:
                    response = {'status': 'fail', 'action': 'register'}
                    send_data(client_socket, 'au', json.dumps(response))
            elif action == 'login':
                if verify_user(username, password):
                    user_role = get_user_role(username)
                    response = {'status': 'ok', 'action': 'login', 'role': user_role}
                    send_data(client_socket, 'au', json.dumps(response))
                    print(f"[LOGIN] User logged in: {username} ({user_role})")
                    return username
                else:
                    response = {'status': 'fail', 'action': 'login'}
                    send_data(client_socket, 'au', json.dumps(response))
        else:
            return None

def register_user(username, password, role='student'):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', (username, password_hash, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if result:
        password_hash = result[0]
        return hashlib.sha256(password.encode()).hexdigest() == password_hash
    return False

def get_user_role(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT role FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return result[0]
    else:
        return 'student'

def handle_message(msg_data, sender):
    message = msg_data.get('message')
    if sender in muted_users:
        send_system_message("You are muted and cannot send messages.", recipient=sender)
        return

    recipient = msg_data.get('recipient')
    if recipient:
        # Private message
        send_private_message(recipient, message, sender)
    else:
        # Broadcast message to channel
        broadcast_message(message, sender)
    # Store the message in the database
    store_message(sender, clients[sender]['channel'], message)

def store_message(sender, channel, message):
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO messages (sender, channel, message) VALUES (?, ?, ?)', (sender, channel, message))
        conn.commit()
    except Exception as e:
        print(f"Error storing message: {e}")
    finally:
        conn.close()

def handle_command(msg_data, sender):
    command = msg_data.get('command')
    args = msg_data.get('args', {})
    user_role = clients[sender]['role']

    if command == 'mute':
        if user_role in ['teacher', 'admin']:
            target_user = args.get('target')
            if target_user and target_user in clients:
                muted_users.add(target_user)
                send_system_message(f"{target_user} has been muted by {sender}.")
            else:
                send_system_message(f"User {target_user} does not exist.", recipient=sender)
        else:
            send_system_message("You do not have permission to mute users.", recipient=sender)
    elif command == 'unmute':
        if user_role in ['teacher', 'admin']:
            target_user = args.get('target')
            if target_user and target_user in muted_users:
                muted_users.remove(target_user)
                send_system_message(f"{target_user} has been unmuted by {sender}.")
            else:
                send_system_message(f"User {target_user} is not muted.", recipient=sender)
        else:
            send_system_message("You do not have permission to unmute users.", recipient=sender)
    elif command == 'announce':
        if user_role in ['teacher', 'admin']:
            announcement = args.get('message')
            send_announcement(announcement, sender)
        else:
            send_system_message("You do not have permission to send announcements.", recipient=sender)
    elif command == 'create_channel':
        channel_name = args.get('channel_name')
        create_channel(channel_name, sender)
    elif command == 'join_channel':
        channel_name = args.get('channel_name')
        join_channel(channel_name, sender)
    elif command == 'leave_channel':
        leave_channel(sender)
    else:
        send_system_message("Unknown command.", recipient=sender)

def create_channel(channel_name, sender):
    if not channel_name:
        send_system_message("Channel name cannot be empty.", recipient=sender)
        return
    with channels_lock:
        if channel_name in channels:
            send_system_message(f"Channel '{channel_name}' already exists.", recipient=sender)
            return
        channels[channel_name] = set()
        channels[channel_name].add(sender)
        current_channel = clients[sender]['channel']
        channels[current_channel].remove(sender)
        if not channels[current_channel]:
            del channels[current_channel]
        clients[sender]['channel'] = channel_name
    # Store the channel in the database
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO channels (name, created_by) VALUES (?, ?)', (channel_name, sender))
        conn.commit()
    except Exception as e:
        print(f"Error creating channel in database: {e}")
    finally:
        conn.close()
    send_system_message(f"Channel '{channel_name}' has been created.", recipient=sender)
    send_system_message(f"{sender} has joined the channel '{channel_name}'.", channel=channel_name)
    broadcast_channel_list()
    broadcast_user_list()
    # Send recent messages to the user
    recent_messages = get_recent_messages(channel_name)
    for msg in recent_messages:
        msg_data = {'sender': msg[0], 'message': msg[1], 'timestamp': msg[2]}
        send_data(clients[sender]['socket'], 'ms', json.dumps(msg_data))

def join_channel(channel_name, sender):
    if not channel_name:
        send_system_message("Channel name cannot be empty.", recipient=sender)
        return
    with channels_lock:
        if channel_name not in channels:
            send_system_message(f"Channel '{channel_name}' does not exist.", recipient=sender)
            return
        current_channel = clients[sender]['channel']
        if current_channel != channel_name:
            channels[current_channel].remove(sender)
            if not channels[current_channel]:
                del channels[current_channel]
            clients[sender]['channel'] = channel_name
            channels[channel_name].add(sender)
        else:
            send_system_message(f"You are already in channel '{channel_name}'.", recipient=sender)
            return
    send_system_message(f"{sender} has joined the channel '{channel_name}'.", channel=channel_name)
    broadcast_user_list()
    # Send recent messages to the user
    recent_messages = get_recent_messages(channel_name)
    for msg in recent_messages:
        msg_data = {'sender': msg[0], 'message': msg[1], 'timestamp': msg[2]}
        send_data(clients[sender]['socket'], 'ms', json.dumps(msg_data))

def leave_channel(sender):
    current_channel = clients[sender]['channel']
    if current_channel == 'General':
        send_system_message("You are already in the General channel.", recipient=sender)
    else:
        with channels_lock:
            channels[current_channel].remove(sender)
            if not channels[current_channel]:
                del channels[current_channel]
            clients[sender]['channel'] = 'General'
            channels['General'].add(sender)
        send_system_message(f"{sender} has left the channel.", channel=current_channel)
        send_system_message(f"{sender} has joined the General channel.", channel='General')
        broadcast_user_list()
        # Send recent messages from 'General' channel
        recent_messages = get_recent_messages('General')
        for msg in recent_messages:
            msg_data = {'sender': msg[0], 'message': msg[1], 'timestamp': msg[2]}
            send_data(clients[sender]['socket'], 'ms', json.dumps(msg_data))

def get_recent_messages(channel, limit=50):
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''
            SELECT sender, message, timestamp FROM messages
            WHERE channel = ?
            ORDER BY timestamp ASC
            LIMIT ?
        ''', (channel, limit))
        result = c.fetchall()
        return result
    except Exception as e:
        print(f"Error retrieving messages: {e}")
        return []
    finally:
        conn.close()

def handle_file_upload(client_socket, msg_data, sender):
    user_role = clients[sender]['role']
    if user_role in ['teacher', 'admin']:
        filename = msg_data.get('filename')
        file_size = msg_data.get('file_size')
        response = {'status': 'ready'}
        send_data(client_socket, 'fs', json.dumps(response))

        # Receive the file
        with open(f"shared_files/{filename}", "wb") as f:
            received_size = 0
            while received_size < file_size:
                data_type, data = recv_data(client_socket)
                if data_type == 'fd':  # File Data
                    f.write(data)
                    received_size += len(data)
                else:
                    break
        if received_size == file_size:
            shared_files.append(filename)
            send_system_message(f"File '{filename}' has been shared by {sender}.", channel=clients[sender]['channel'])
            broadcast_file_list()
        else:
            send_system_message(f"Failed to receive the complete file '{filename}' from {sender}.", recipient=sender)
    else:
        send_system_message("You do not have permission to share files.", recipient=sender)

def handle_file_request(client_socket, msg_data, sender):
    filename = msg_data.get('filename')
    if filename in shared_files:
        file_size = os.path.getsize(f"shared_files/{filename}")
        header = {'filename': filename, 'file_size': file_size}
        send_data(client_socket, 'fi', json.dumps(header))
        with open(f"shared_files/{filename}", "rb") as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                send_data(client_socket, 'fd', data)
    else:
        send_system_message(f"File '{filename}' does not exist.", recipient=sender)

def broadcast_message(message, sender):
    sender_channel = clients[sender]['channel']
    msg_data = {
        'sender': sender,
        'message': message,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    with channels_lock:
        for user in channels.get(sender_channel, set()):
            if user != sender:
                try:
                    send_data(clients[user]['socket'], 'ms', json.dumps(msg_data))
                except Exception as e:
                    print(f"Error broadcasting message to {user}: {e}")

def send_private_message(recipient, message, sender):
    if recipient in clients:
        msg_data = {
            'sender': sender,
            'message': message,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        try:
            send_data(clients[recipient]['socket'], 'pm', json.dumps(msg_data))
        except Exception as e:
            print(f"Error sending private message to {recipient}: {e}")
    else:
        send_system_message(f"User {recipient} does not exist.", recipient=sender)

def send_system_message(message, recipient=None, exclude=[], channel=None):
    msg_data = {'message': message}
    if recipient:
        try:
            send_data(clients[recipient]['socket'], 'sy', json.dumps(msg_data))
        except Exception as e:
            print(f"Error sending system message to {recipient}: {e}")
    else:
        with channels_lock:
            if channel and channel in channels:
                target_users = channels[channel]
            else:
                target_users = clients.keys()
            for user in target_users:
                if user not in exclude:
                    try:
                        send_data(clients[user]['socket'], 'sy', json.dumps(msg_data))
                    except Exception as e:
                        print(f"Error sending system message to {user}: {e}")

def send_announcement(message, sender):
    msg_data = {'sender': sender, 'message': message}
    with clients_lock:
        for user, info in clients.items():
            try:
                send_data(info['socket'], 'an', json.dumps(msg_data))
            except Exception as e:
                print(f"Error sending announcement to {user}: {e}")

def broadcast_user_list():
    with clients_lock:
        for user, info in clients.items():
            user_channel = info['channel']
            with channels_lock:
                user_list = [{'username': u, 'role': clients[u]['role']} for u in channels.get(user_channel, [])]
            msg_data = {'users': user_list}
            try:
                send_data(info['socket'], 'ul', json.dumps(msg_data))
            except Exception as e:
                print(f"Error broadcasting user list to {user}: {e}")

def broadcast_file_list():
    msg_data = {'files': shared_files}
    with clients_lock:
        for user, info in clients.items():
            try:
                send_data(info['socket'], 'fl', json.dumps(msg_data))
            except Exception as e:
                print(f"Error broadcasting file list to {user}: {e}")

def broadcast_channel_list():
    with channels_lock:
        channel_list = list(channels.keys())
    msg_data = {'channels': channel_list}
    with clients_lock:
        for user, info in clients.items():
            try:
                send_data(info['socket'], 'cl', json.dumps(msg_data))
            except Exception as e:
                print(f"Error broadcasting channel list to {user}: {e}")

def send_channel_list(client_socket):
    with channels_lock:
        channel_list = list(channels.keys())
    msg_data = {'channels': channel_list}
    try:
        send_data(client_socket, 'cl', json.dumps(msg_data))
    except Exception as e:
        print(f"Error sending channel list: {e}")

# Setup server
if not os.path.exists('shared_files'):
    os.makedirs('shared_files')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 5555))  # Use any IP address and port 5555
server.listen()

print("[SERVER STARTED] Waiting for connections...")

# Accept new client connections
while True:
    client_socket, client_address = server.accept()
    threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
