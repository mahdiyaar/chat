import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import socket
import time
import hashlib
import os
from cryptography.fernet import Fernet
import json
import socket
import threading
import time

import random
from cryptography.fernet import Fernet

import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime


class OnionRouter:
    def __init__(self, peers):
        self.peers = peers

    def create_onion(self, message, destination):

        if not self.peers:
            return message

        path_length = min(3, len(self.peers))
        path = random.sample(self.peers, path_length)

        if destination not in path:
            path.append(destination)

        encrypted = message.encode()
        for peer in reversed(path):
            key = self._get_key_for_peer(peer)
            cipher = Fernet(key)
            encrypted = cipher.encrypt(encrypted)

        return {
            'path': [p for p in path],
            'encrypted_data': encrypted
        }

    def peel_onion(self, onion_packet):
        """رمزگشایی یک لایه از پیام onion"""
        if not onion_packet['path']:
            return onion_packet['encrypted_data'].decode()

        current_peer = onion_packet['path'].pop(0)
        key = self._get_key_for_peer(current_peer)
        cipher = Fernet(key)

        try:
            decrypted = cipher.decrypt(onion_packet['encrypted_data'])
            return {
                'path': onion_packet['path'],
                'encrypted_data': decrypted
            }
        except:
            raise ValueError("Decryption failed - possibly wrong key")

    def _get_key_for_peer(self, peer):
        return Fernet.generate_key()







def setup_logging(username):

    if not os.path.exists('logs'):
        os.makedirs('logs')

    log_filename = f"logs/report_{username}_{datetime.now().strftime('%Y%m%d')}.log"

    logger = logging.getLogger('SecuriChatLogger')
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s | Protocol: %(protocol)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger

class SecuriChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("SecuriChat")


        self.username = ""
        self.peer_discovery = PeerDiscovery()
        self.current_chat = None
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)

        self._setup_ui()

    def _setup_ui(self):

        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.login_frame = ttk.Frame(self.main_frame)
        self.login_frame.pack(fill=tk.X)

        ttk.Label(self.login_frame, text="Username:").pack(side=tk.LEFT)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        self.login_btn = ttk.Button(self.login_frame, text="Login", command=self._login)
        self.login_btn.pack(side=tk.LEFT)

        self.chat_frame = ttk.Frame(self.main_frame)


        # لیست کاربران آنلاین
        self.online_users_frame = ttk.LabelFrame(self.chat_frame, text="Online Users", padding="5")
        self.online_users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        self.online_users_list = tk.Listbox(self.online_users_frame)
        self.online_users_list.pack(fill=tk.BOTH, expand=True)
        self.online_users_list.bind('<<ListboxSelect>>', self._select_user)

        # تاریخچه چت
        self.chat_history_frame = ttk.LabelFrame(self.chat_frame, text="Chat History", padding="5")
        self.chat_history_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.chat_history = scrolledtext.ScrolledText(self.chat_history_frame, state='disabled')
        self.chat_history.pack(fill=tk.BOTH, expand=True)

        # ورودی پیام
        self.message_frame = ttk.Frame(self.chat_frame)
        self.message_frame.pack(fill=tk.X, pady=5)

        self.message_entry = ttk.Entry(self.message_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind('<Return>', self._send_message)

        self.send_btn = ttk.Button(self.message_frame, text="Send", command=self._send_message)
        self.send_btn.pack(side=tk.LEFT)

        self.file_btn = ttk.Button(self.message_frame, text="Send File", command=self._send_file)
        self.file_btn.pack(side=tk.LEFT, padx=5)

        # مخفی کردن بخش چت تا زمان ورود کاربر
        self.chat_frame.pack_forget()

    def _login(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Username cannot be empty!")
            return

        self.username = username
        self.logger = setup_logging(username)
        self.logger.info("Application started", extra={'protocol': 'INIT'})
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        self.peer_discovery.start_discovery()

        self._update_online_users()

    def _update_online_users(self):
        if not self.username:
            return

        online_users = self.peer_discovery.get_online_peers()

        self.online_users_list.delete(0, tk.END)
        for user in online_users:
            self.online_users_list.insert(tk.END, user)

        self.root.after(5000, self._update_online_users)

    def _select_user(self, event):
        selection = self.online_users_list.curselection()
        if selection:
            self.current_chat = self.online_users_list.get(selection[0])
            self._update_chat_title()

    def _update_chat_title(self):
        if self.current_chat:
            self.chat_history_frame.config(text=f"Chat with {self.current_chat}")
        else:
            self.chat_history_frame.config(text="Chat History")

    def _send_message(self, event=None):
        if not self.current_chat:
            messagebox.showerror("Error", "Please select a user to chat with!")
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        encrypted_msg = self._encrypt_message(message)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.current_chat, 37021))
                s.sendall(encrypted_msg)
            self.logger.info(
                f"Message sent: {message[:30]}...",
                extra={'protocol': 'tcp'}
            )

            self._display_message(self.username, message)
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
            self.logger.error(
                f"Failed to send message: {str(e)}",
                extra={'protocol': 'tcp'}
            )

    def _send_file(self):
        if not self.current_chat:
            messagebox.showerror("Error", "Please select a user to chat with!")
            return

        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()

            filename = os.path.basename(filepath)
            file_msg = {
                'type': 'file',
                'name': filename,
                'data': file_data
            }
            serialized = json.dumps(file_msg).encode()
            encrypted = self._encrypt_message(serialized)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.current_chat, 37021))
                s.sendall(encrypted)

            self._display_message(self.username, f"Sent file: {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {e}")

    def _encrypt_message(self, message):
        if isinstance(message, str):
            message = message.encode()
        return self.cipher.encrypt(message)

    def _decrypt_message(self, encrypted):
        return self.cipher.decrypt(encrypted)

    def _display_message(self, sender, message):

        self.chat_history.config(state='normal')
        self.chat_history.insert(tk.END, f"{sender}: {message}\n")
        self.chat_history.config(state='disabled')
        self.chat_history.see(tk.END)

    def start_receiving(self):
        threading.Thread(target=self._receive_messages, daemon=True).start()

    def _receive_messages(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', 37021))
            s.listen()

            while True:
                conn, addr = s.accept()
                try:
                    data = conn.recv(4096)
                    if data:
                        decrypted = self._decrypt_message(data)

                        try:
                            msg = json.loads(decrypted)
                            if msg.get('type') == 'file':
                                self._handle_received_file(msg, addr[0])
                                continue
                        except:
                            pass

                        self._display_message(addr[0], decrypted.decode())

                    self.logger.info(
                        f"Message received: {decrypted.decode()}...",
                        extra={'protocol': 'tcp'}
                    )
                except Exception as e:
                    print(f"Error receiving message: {e}")
                finally:
                    conn.close()

    def _handle_received_file(self, file_msg, sender):

        filename = file_msg['name']
        file_data = file_msg['data']

        save_path = filedialog.asksaveasfilename(
            initialfile=filename,
            title="Save received file"
        )

        if save_path:
            try:
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                self._display_message(sender, f"Sent file: {filename} (saved to {save_path})")
            except Exception as e:
                self._display_message(sender, f"Failed to save file: {e}")
        else:
            self._display_message(sender, f"Sent file: {filename} (not saved)")



class PeerDiscovery:
    def __init__(self, port=37020):
        self.port = port
        self.online_peers = {}
        self.running = False

    def start_discovery(self):

        self.running = True
        threading.Thread(target=self._listen_for_peers, daemon=True).start()
        threading.Thread(target=self._broadcast_presence, daemon=True).start()

    def stop_discovery(self):
        self.running = False

    def _broadcast_presence(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        while self.running:
            try:
                message = b"SECURICHAT_PRESENCE"
                sock.sendto(message, ('<broadcast>', self.port))
                time.sleep(5)
            except Exception as e:
                print(f"Broadcast error: {e}")

    def _listen_for_peers(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.port))

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                if data == b"SECURICHAT_PRESENCE":
                    ip = addr[0]
                    self.online_peers[ip] = time.time()
                    self._clean_old_peers()
            except Exception as e:
                print(f"Peer discovery error: {e}")

    def _clean_old_peers(self):
        current_time = time.time()
        inactive_peers = [
            ip for ip, last_seen in self.online_peers.items()
            if current_time - last_seen > 15
        ]
        for ip in inactive_peers:
            del self.online_peers[ip]

    def get_online_peers(self):
        self._clean_old_peers()
        return list(self.online_peers.keys())


if __name__ == "__main__":
    root = tk.Tk()
    client = SecuriChatClient(root)
    client.start_receiving()
    root.mainloop()