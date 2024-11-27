import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, ttk, filedialog
import os
import json
import hashlib
import emoji

HEADER_SIZE = 10  # 10 bytes for header

class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.username = None
        self.role = None
        self.muted = False
        self.file_list = []
        self.save_path = ""
        self.uploading_file = False  # Flag to indicate file upload in progress
        self.upload_file_info = None  # Store file info during upload
        self.channel_list = []
        self.current_channel = 'General'

        self.root = tk.Tk()
        self.root.title("Classroom Chat")

        # Initialize GUI elements
        self.setup_gui()

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        # Lock for synchronizing socket access
        self.recv_lock = threading.Lock()

        # Start the authentication process
        self.authenticate()

        # Start a thread to listen for incoming messages
        threading.Thread(target=self.receive_messages, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def send_data(self, data_type, data):
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        length = len(data_bytes)
        header = f"{length:<8}{data_type:<2}".encode('utf-8')
        try:
            self.client_socket.sendall(header + data_bytes)
        except Exception as e:
            print(f"Error sending data: {e}")

    def recv_data(self):
        with self.recv_lock:
            try:
                # Receive header
                header = b''
                while len(header) < HEADER_SIZE:
                    part = self.client_socket.recv(HEADER_SIZE - len(header))
                    if not part:
                        return None, None
                    header += part
                length = int(header[:8].strip())
                data_type = header[8:10].decode('utf-8').strip()
                # Receive data
                data = b''
                while len(data) < length:
                    part = self.client_socket.recv(length - len(data))
                    if not part:
                        break
                    data += part
                return data_type, data
            except Exception as e:
                print(f"Error receiving data: {e}")
                return None, None

    def setup_gui(self):
        # Use ttk for improved styling
        self.style = ttk.Style(self.root)
        self.style.theme_use('clam')

        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label='Settings', menu=settings_menu)
        settings_menu.add_command(label='Toggle Dark Mode', command=self.toggle_dark_mode)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label='Help', menu=help_menu)
        help_menu.add_command(label='About', command=self.show_about)

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left frame for chat messages
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Channel selection frame
        channel_frame = ttk.Frame(left_frame)
        channel_frame.pack(fill=tk.X, padx=10, pady=5)

        self.channel_label = ttk.Label(channel_frame, text="Channel:")
        self.channel_label.pack(side=tk.LEFT, padx=5)

        self.channel_var = tk.StringVar(value=self.current_channel)
        self.channel_menu = ttk.Combobox(channel_frame, textvariable=self.channel_var, state='readonly')
        self.channel_menu.pack(side=tk.LEFT, padx=5)
        self.channel_menu.bind("<<ComboboxSelected>>", self.on_channel_selected)

        self.create_channel_button = ttk.Button(channel_frame, text="Create Channel", command=self.create_channel)
        self.create_channel_button.pack(side=tk.LEFT, padx=5)

        # Chat display area
        self.chat_box = scrolledtext.ScrolledText(left_frame, state='disabled', wrap='word')
        self.chat_box.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        # Right frame for user list and file list
        right_frame = ttk.Frame(main_frame, width=200)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)

        # User list
        self.user_list_label = ttk.Label(right_frame, text="Online Users")
        self.user_list_label.pack(pady=5)

        self.user_listbox = tk.Listbox(right_frame)
        self.user_listbox.pack(padx=10, pady=5, fill=tk.Y, expand=True)

        # File list
        self.file_list_label = ttk.Label(right_frame, text="Shared Files")
        self.file_list_label.pack(pady=5)

        self.file_listbox = tk.Listbox(right_frame)
        self.file_listbox.pack(padx=10, pady=5, fill=tk.Y, expand=True)
        self.file_listbox.bind('<Double-1>', self.download_file)

        # Entry field and send button
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(fill=tk.X)

        self.msg_entry = ttk.Entry(bottom_frame)
        self.msg_entry.pack(padx=10, pady=10, side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", self.send_message)

        self.send_button = ttk.Button(bottom_frame, text="Send", command=self.send_message)
        self.send_button.pack(padx=5, pady=10, side=tk.LEFT)

        # Emoticon button
        self.emoticon_button = ttk.Button(bottom_frame, text="😊", command=self.insert_emoticon)
        self.emoticon_button.pack(padx=5, pady=10, side=tk.LEFT)

        # File share button (will be enabled/disabled based on role)
        self.file_share_button = ttk.Button(bottom_frame, text="Share File", command=self.share_file)
        self.file_share_button.pack(padx=5, pady=10, side=tk.LEFT)

        self.file_share_button.config(state='disabled')  # Disabled until role is known

        self.moderation_menu = tk.Menu(self.root, tearoff=0)

    def authenticate(self):
        # Ask the user to choose between login or register
        action = simpledialog.askstring("Login or Register", "Type 'login' to log in or 'register' to register:", parent=self.root)
        if action not in ['login', 'register']:
            messagebox.showerror("Invalid Action", "Please enter 'login' or 'register'.")
            self.root.destroy()
            return

        self.username = simpledialog.askstring("Username", "Enter your username:", parent=self.root)
        password = simpledialog.askstring("Password", "Enter your password:", show='*', parent=self.root)

        if action == 'register':
            role = simpledialog.askstring("Role", "Enter your role ('student', 'teacher', 'admin'):", parent=self.root)
            if role not in ['student', 'teacher', 'admin']:
                messagebox.showerror("Invalid Role", "Role must be 'student', 'teacher', or 'admin'.")
                self.root.destroy()
                return
        else:
            role = None  # Role is not needed during login

        credentials = {
            'action': action,
            'username': self.username,
            'password': password
        }
        if role:
            credentials['role'] = role

        self.send_data('au', json.dumps(credentials))

        data_type, data = self.recv_data()
        if data_type == 'au':
            response = json.loads(data.decode('utf-8'))
            if response['status'] == 'ok':
                if action == 'register':
                    messagebox.showinfo("Registration Successful", "You have registered successfully!")
                    self.role = response.get('role', 'student')
                elif action == 'login':
                    messagebox.showinfo("Login Successful", "You have logged in successfully!")
                    self.role = response.get('role', 'student')
                self.root.title(f"Classroom Chat - {self.username}")
                self.update_ui_for_role()
            else:
                messagebox.showerror("Authentication Failed", "Failed to authenticate. Please try again.")
                self.root.destroy()
        else:
            messagebox.showerror("Authentication Failed", "Failed to authenticate. Please try again.")
            self.root.destroy()

    def update_ui_for_role(self):
        if self.role in ['teacher', 'admin']:
            # Enable file sharing button
            self.file_share_button.config(state='normal')
            # Add moderation tools
            self.user_listbox.bind('<Button-3>', self.show_moderation_menu)
        else:
            # Disable file sharing button
            self.file_share_button.config(state='disabled')
            self.user_listbox.unbind('<Button-3>')

    def receive_messages(self):
        while True:
            try:
                data_type, data = self.recv_data()
                if data_type:
                    if data_type == 'ms':  # Message
                        msg_data = json.loads(data.decode('utf-8'))
                        sender = msg_data.get('sender')
                        message = msg_data.get('message')
                        timestamp = msg_data.get('timestamp')
                        self.root.after(0, self.display_message, f"{sender}: {message}", timestamp)
                    elif data_type == 'pm':  # Private Message
                        msg_data = json.loads(data.decode('utf-8'))
                        sender = msg_data.get('sender')
                        message = msg_data.get('message')
                        timestamp = msg_data.get('timestamp')
                        self.root.after(0, self.display_message, f"(Private) {sender}: {message}", timestamp)
                    elif data_type == 'an':  # Announcement
                        msg_data = json.loads(data.decode('utf-8'))
                        self.root.after(0, self.display_announcement, f"Announcement from {msg_data['sender']}: {msg_data['message']}")
                    elif data_type == 'sy':  # System Message
                        msg_data = json.loads(data.decode('utf-8'))
                        self.root.after(0, self.display_system_message, msg_data['message'])
                    elif data_type == 'ul':  # User List
                        msg_data = json.loads(data.decode('utf-8'))
                        self.root.after(0, self.update_user_list, msg_data['users'])
                    elif data_type == 'fl':  # File List
                        msg_data = json.loads(data.decode('utf-8'))
                        self.root.after(0, self.update_file_list, msg_data['files'])
                    elif data_type == 'fi':  # File Info (start of file transfer)
                        msg_data = json.loads(data.decode('utf-8'))
                        threading.Thread(target=self.receive_file, args=(msg_data,), daemon=True).start()
                    elif data_type == 'fs':  # File Status (server ready to receive file)
                        if self.uploading_file:
                            response = json.loads(data.decode('utf-8'))
                            if response.get('status') == 'ready':
                                threading.Thread(target=self.send_file_data, daemon=True).start()
                            else:
                                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to share the file."))
                                self.uploading_file = False
                    elif data_type == 'cl':  # Channel List
                        msg_data = json.loads(data.decode('utf-8'))
                        self.root.after(0, self.update_channel_list, msg_data['channels'])
                    else:
                        pass  # Handle other data types
                else:
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def send_message(self, event=None):
        if self.muted:
            messagebox.showwarning("Muted", "You are muted and cannot send messages.")
            return

        message = self.msg_entry.get()
        recipient = self.get_selected_user()
        if message:
            message = emoji.emojize(message)
            if recipient and recipient != self.username:
                msg_data = {
                    'recipient': recipient,
                    'message': message
                }
                self.root.after(0, self.display_message, f"(Private to {recipient}) Me: {message}")
                self.send_data('ms', json.dumps(msg_data))
            else:
                msg_data = {
                    'message': message
                }
                self.root.after(0, self.display_message, f"Me: {message}")
                self.send_data('ms', json.dumps(msg_data))
            self.msg_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Empty Message", "You cannot send an empty message.")

    def display_message(self, message, timestamp=None):
        self.chat_box.config(state='normal')
        if timestamp:
            self.chat_box.insert(tk.END, f"[{timestamp}] {message}\n")
        else:
            self.chat_box.insert(tk.END, f"{message}\n")
        self.chat_box.config(state='disabled')
        self.chat_box.see(tk.END)

    def display_announcement(self, message):
        self.chat_box.config(state='normal')
        self.chat_box.insert(tk.END, f"\n=== {message} ===\n", 'announcement')
        self.chat_box.tag_config('announcement', foreground='red', justify='center')
        self.chat_box.config(state='disabled')
        self.chat_box.see(tk.END)

    def display_system_message(self, message):
        self.chat_box.config(state='normal')
        self.chat_box.insert(tk.END, f"[System]: {message}\n", 'system')
        self.chat_box.tag_config('system', foreground='blue')
        self.chat_box.config(state='disabled')
        self.chat_box.see(tk.END)
        if "muted" in message and self.username in message:
            self.muted = True
        if "unmuted" in message and self.username in message:
            self.muted = False

    def update_user_list(self, users):
        self.user_listbox.delete(0, tk.END)
        for user_info in users:
            user = user_info['username']
            role = user_info['role']
            self.user_listbox.insert(tk.END, f"{user} ({role})")

    def get_selected_user(self):
        selection = self.user_listbox.curselection()
        if selection:
            selected = self.user_listbox.get(selection[0])
            username = selected.split(' ')[0]
            return username
        return None

    def insert_emoticon(self):
        # Simple emoticon insertion
        emoticon = simpledialog.askstring("Insert Emoticon", "Enter the emoticon code (e.g., :smile:)", parent=self.root)
        if emoticon:
            self.msg_entry.insert(tk.END, emoji.emojize(emoticon))

    def share_file(self):
        # Start the file sharing process
        if not self.uploading_file:
            self.uploading_file = True
            threading.Thread(target=self._share_file_thread, daemon=True).start()
        else:
            messagebox.showwarning("File Upload", "A file upload is already in progress.")

    def _share_file_thread(self):
        filename = filedialog.askopenfilename(title="Select File to Share")
        if filename:
            file_size = os.path.getsize(filename)
            basename = os.path.basename(filename)
            self.upload_file_info = {
                'filename': basename,
                'filepath': filename,
                'file_size': file_size
            }
            msg_data = {
                'filename': basename,
                'file_size': file_size
            }
            self.send_data('fu', json.dumps(msg_data))
            # Do not call recv_data here; wait for 'fs' in receive_messages
        else:
            self.uploading_file = False

    def send_file_data(self):
        # Send the file data after receiving 'fs' from the server
        try:
            with open(self.upload_file_info['filepath'], "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.send_data('fd', chunk)
            self.root.after(0, lambda: messagebox.showinfo("File Shared", f"File '{self.upload_file_info['filename']}' has been shared."))
        except Exception as e:
            print(f"Error sending file data: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", "Failed to send the file."))
        finally:
            self.uploading_file = False
            self.upload_file_info = None

    def update_file_list(self, files):
        self.file_list = files
        self.file_listbox.delete(0, tk.END)
        for filename in files:
            self.file_listbox.insert(tk.END, filename)

    def download_file(self, event=None):
        selection = self.file_listbox.curselection()
        if selection:
            filename = self.file_listbox.get(selection[0])
            save_path = filedialog.asksaveasfilename(initialfile=filename, title="Save File As")
            if save_path:
                msg_data = {
                    'filename': filename
                }
                self.save_path = save_path
                self.send_data('fr', json.dumps(msg_data))

    def receive_file(self, msg_data):
        filename = msg_data.get('filename')
        file_size = msg_data.get('file_size')
        try:
            with open(self.save_path, "wb") as f:
                received_size = 0
                while received_size < file_size:
                    data_type, data = self.recv_data()
                    if data_type == 'fd':  # File Data
                        f.write(data)
                        received_size += len(data)
                    else:
                        print(f"Unexpected data type during file transfer: {data_type}")
                        break
            if received_size == file_size:
                self.root.after(0, lambda: messagebox.showinfo("File Downloaded", f"File '{filename}' has been downloaded."))
            else:
                print(f"File size mismatch: expected {file_size}, received {received_size}")
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to download file '{filename}'."))
        except Exception as e:
            print(f"Error receiving file: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to download file '{filename}'."))
        finally:
            self.save_path = ""

    def toggle_dark_mode(self):
        current_theme = self.style.theme_use()
        if current_theme == 'clam':
            self.style.theme_use('alt')
        else:
            self.style.theme_use('clam')

    def show_about(self):
        messagebox.showinfo("About", "Classroom Chat Application\nVersion 1.0\nDeveloped for Classroom Use")

    def on_closing(self):
        try:
            self.client_socket.close()
        except:
            pass
        self.root.destroy()

    def show_moderation_menu(self, event):
        selection = self.user_listbox.curselection()
        if selection:
            selected_user = self.get_selected_user()
            self.moderation_menu.delete(0, tk.END)
            self.moderation_menu.add_command(label="Mute User", command=lambda: self.mute_user(selected_user))
            self.moderation_menu.add_command(label="Unmute User", command=lambda: self.unmute_user(selected_user))
            self.moderation_menu.tk_popup(event.x_root, event.y_root)

    def mute_user(self, target_user):
        self.send_command('mute', {'target': target_user})

    def unmute_user(self, target_user):
        self.send_command('unmute', {'target': target_user})

    def send_command(self, command, args=None):
        msg_data = {'command': command, 'args': args or {}}
        self.send_data('cm', json.dumps(msg_data))

    def create_channel(self):
        channel_name = simpledialog.askstring("Create Channel", "Enter channel name:", parent=self.root)
        if channel_name:
            self.send_command('create_channel', {'channel_name': channel_name})
            # Assume the server adds us to the new channel; update client state
            self.current_channel = channel_name
            self.channel_var.set(channel_name)
            self.chat_box.config(state='normal')
            self.chat_box.delete('1.0', tk.END)
            self.chat_box.config(state='disabled')

    def on_channel_selected(self, event=None):
        selected_channel = self.channel_var.get()
        if selected_channel != self.current_channel:
            self.current_channel = selected_channel
            self.chat_box.config(state='normal')
            self.chat_box.delete('1.0', tk.END)
            self.chat_box.config(state='disabled')
            self.send_command('join_channel', {'channel_name': selected_channel})

    def update_channel_list(self, channels):
        self.channel_list = channels
        self.channel_menu['values'] = channels
        if self.current_channel not in channels:
            self.current_channel = 'General'
            self.channel_var.set('General')
            self.chat_box.config(state='normal')
            self.chat_box.delete('1.0', tk.END)
            self.chat_box.config(state='disabled')
            self.send_command('join_channel', {'channel_name': 'General'})

if __name__ == "__main__":
    client = ChatClient('IP Address daalo', 5555)
