import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image, ImageTk
import stegano.lsb as lsb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
import tempfile
import requests
import io

# Color theme for a sleek, modern look
PRIMARY = "#8be9fd"  # Cyan for buttons
SECONDARY = "#50fa7b"  # Green for accents
DANGER = "#ff5555"  # Red for errors
DARK_BG = "#282a36"  # Dark background
LIGHT_BG = "#44475a"  # Lighter panel background
TEXT_COLOR = "#f8f8f2"  # Off-white text
BUTTON_HOVER = "#6272a4"  # Hover effect for buttons

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steg-Go!!")
        self.root.geometry("650x650")  # Adjusted window size
        self.root.configure(bg=DARK_BG)

        self.loaded_image = None  # Store dropped image path
        self.loaded_file = None  # Store uploaded file path
        self.temp_png = None  # Temporary PNG file for conversions
        self.preview_img = None  # Image preview

        self.create_interface()

    def create_interface(self):
        # Styling for a polished UI
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TLabel", background=DARK_BG, foreground=TEXT_COLOR)
        style.configure("TButton", background=PRIMARY, foreground="#000", font=("Segoe UI", 9, "bold"))
        style.map("TButton",
                  background=[("active", BUTTON_HOVER), ("pressed", SECONDARY)],
                  foreground=[("active", "#fff")])

        # Main container with reduced padding
        main_frame = tk.Frame(self.root, bg=DARK_BG)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Fun title with smaller font
        title_label = tk.Label(main_frame, text="🧠 Steg-Go!!", font=("Segoe UI", 24, "bold"),
                               fg=PRIMARY, bg=DARK_BG)
        title_label.pack(pady=(0, 10))

        # Split layout into two panels
        content_frame = tk.Frame(main_frame, bg=DARK_BG)
        content_frame.pack(fill="both", expand=True)

        # Left panel: Image drop zone and URL input
        left_frame = tk.Frame(content_frame, bg=LIGHT_BG, bd=2, relief="ridge")
        left_frame.pack(side=tk.LEFT, padx=5, pady=5, fill="y")

        self.drop_zone = tk.Label(left_frame, text="📷 Drop PNG/BMP/JPG Here", font=("Segoe UI", 11, "bold"),
                                  fg=TEXT_COLOR, bg=LIGHT_BG, width=20, height=10, bd=2, relief="sunken")
        self.drop_zone.pack(padx=5, pady=5)
        self.drop_zone.drop_target_register(DND_FILES)
        self.drop_zone.dnd_bind('<<Drop>>', self.handle_image_drop)

        # URL input for image
        url_frame = tk.LabelFrame(left_frame, text="Image URL", font=("Segoe UI", 9),
                                  fg=SECONDARY, bg=LIGHT_BG)
        url_frame.pack(pady=5, fill="x", padx=5)
        self.url_field = tk.Entry(url_frame, width=20, bg=DARK_BG, fg=TEXT_COLOR, font=("Segoe UI", 9))
        self.url_field.pack(side=tk.LEFT, padx=5, pady=5)
        self.load_url_button = tk.Button(url_frame, text="🌐 Load", command=self.load_image_from_url,
                                         bg=PRIMARY, fg="#000", font=("Segoe UI", 9, "bold"),
                                         width=8, bd=0, activebackground=BUTTON_HOVER)
        self.load_url_button.pack(side=tk.LEFT, padx=5)

        # File upload button
        self.file_button = tk.Button(left_frame, text="📂 Upload File", command=self.upload_file,
                                     bg=PRIMARY, fg="#000", font=("Segoe UI", 9, "bold"),
                                     width=15, bd=0, activebackground=BUTTON_HOVER)
        self.file_button.pack(pady=5)

        # Right panel: Controls and preview
        right_frame = tk.Frame(content_frame, bg=DARK_BG)
        right_frame.pack(side=tk.RIGHT, padx=5, pady=5, fill="both", expand=True)

        # Image preview area
        preview_frame = tk.LabelFrame(right_frame, text="Image Preview", font=("Segoe UI", 9),
                                      fg=SECONDARY, bg=LIGHT_BG, labelanchor="n")
        preview_frame.pack(pady=5, fill="x")
        self.preview_label = tk.Label(preview_frame, bg=LIGHT_BG, width=30, height=8)
        self.preview_label.pack(padx=5, pady=5)

        # Secret message input
        msg_frame = tk.LabelFrame(right_frame, text="Secret Message or File Content", font=("Segoe UI", 9),
                                  fg=SECONDARY, bg=LIGHT_BG)
        msg_frame.pack(pady=5, fill="x")
        self.message_box = tk.Text(msg_frame, height=3, width=35, bg=DARK_BG, fg=TEXT_COLOR, font=("Segoe UI", 9))
        self.message_box.pack(padx=5, pady=5)

        # Password input
        pwd_frame = tk.LabelFrame(right_frame, text="Password (Optional)", font=("Segoe UI", 9),
                                  fg=SECONDARY, bg=LIGHT_BG)
        pwd_frame.pack(pady=5, fill="x")
        self.password_field = tk.Entry(pwd_frame, width=35, show="*", bg=DARK_BG, fg=TEXT_COLOR, font=("Segoe UI", 9))
        self.password_field.pack(padx=5, pady=5)

        # Action buttons
        button_frame = tk.Frame(right_frame, bg=DARK_BG)
        button_frame.pack(pady=10)

        self.encode_button = tk.Button(button_frame, text="🔒 Encode", command=self.hide_message,
                                       bg=PRIMARY, fg="#000", font=("Segoe UI", 9, "bold"),
                                       width=12, bd=0, activebackground=BUTTON_HOVER)
        self.encode_button.pack(side=tk.LEFT, padx=5)

        self.decode_button = tk.Button(button_frame, text="🔓 Decode", command=self.reveal_message,
                                       bg="#bd93f9", fg="#000", font=("Segoe UI", 9, "bold"),
                                       width=12, bd=0, activebackground=BUTTON_HOVER)
        self.decode_button.pack(side=tk.LEFT, padx=5)

        # Status bar
        self.status_var = tk.StringVar(value="🔹 Ready to Stego!")
        self.status_label = tk.Label(right_frame, textvariable=self.status_var, fg=SECONDARY, bg=DARK_BG,
                                     font=("Segoe UI", 8, "italic"))
        self.status_label.pack(pady=(5, 2))

    def handle_image_drop(self, event):
        file_path = os.path.normpath(event.data.strip('{}'))
        if self.is_valid_image(file_path):
            self.loaded_image = file_path
            self.show_preview()
            self.status_var.set(f"✅ Loaded image: {os.path.basename(file_path)}")
        else:
            self.status_var.set("❌ Only PNG, BMP, or JPG files allowed!")
            self.loaded_image = None

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*"), ("Text files", "*.txt")])
        if file_path:
            self.loaded_file = file_path
            if file_path.lower().endswith('.txt'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        self.message_box.delete("1.0", tk.END)
                        self.message_box.insert(tk.END, content)
                    self.status_var.set(f"✅ Loaded text file: {os.path.basename(file_path)}")
                except Exception as e:
                    self.status_var.set(f"❌ Failed to load text file: {str(e)}")
            else:
                self.status_var.set(f"✅ Loaded file: {os.path.basename(file_path)}")

    def load_image_from_url(self):
        url = self.url_field.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter an image URL!")
            return
        try:
            self.status_var.set("🌐 Downloading image... Please wait.")
            self.root.update()
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            img_data = response.content
            img = Image.open(io.BytesIO(img_data))
            if img.format not in ["PNG", "BMP", "JPEG"]:
                raise ValueError("Only PNG, BMP, or JPG files allowed!")
            temp_file = tempfile.NamedTemporaryFile(suffix=f".{img.format.lower()}", delete=False)
            img.save(temp_file.name)
            img.close()
            self.loaded_image = temp_file.name
            self.show_preview()
            self.status_var.set(f"✅ Loaded image from URL")
        except Exception as e:
            self.status_var.set(f"❌ Failed to load image from URL: {str(e)}")
            self.loaded_image = None

    def is_valid_image(self, path):
        if not path or not os.path.exists(path):
            return False
        try:
            img = Image.open(path)
            is_valid = img.format in ["PNG", "BMP", "JPEG"]
            img.close()
            return is_valid
        except:
            return False

    def show_preview(self):
        if self.loaded_image:
            try:
                img = Image.open(self.loaded_image).resize((200, 120), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                self.preview_label.configure(image=photo)
                self.preview_label.image = photo
            except:
                self.status_var.set("⚠️ Failed to load preview!")

    def convert_to_png(self, image_path):
        if image_path.lower().endswith(('.jpg', '.jpeg')):
            try:
                img = Image.open(image_path).convert("RGB")
                temp_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
                img.save(temp_file.name, "PNG")
                img.close()
                self.temp_png = temp_file.name
                return self.temp_png
            except Exception as e:
                raise Exception(f"Failed to convert JPG to PNG: {str(e)}")
        return image_path

    def encrypt_data(self, data, password):
        if not password:
            return data
        try:
            key = pad(password.encode('utf-8'), 32)
            cipher = AES.new(key, AES.MODE_CBC)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            iv = base64.b64encode(cipher.iv).decode('utf-8')
            ct = base64.b64encode(cipher_text).decode('utf-8')
            return f"{iv}:{ct}".encode('utf-8')
        except Exception as e:
            raise Exception(f"Encryption error: {str(e)}")

    def decrypt_data(self, data, password):
        if not password:
            if isinstance(data, bytes):
                return data
            return data.encode('utf-8')
        try:
            if isinstance(data, bytes):
                data_str = data.decode('utf-8', errors='ignore')
            else:
                data_str = str(data)
            iv, ct = data_str.split(':')
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            key = pad(password.encode('utf-8'), 32)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            plain_data = unpad(cipher.decrypt(ct), AES.block_size)
            return plain_data
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)} - Check password or image")

    def hide_message(self):
        if not self.loaded_image:
            messagebox.showerror("Error", "Please drop or load an image first!")
            return

        data_to_hide = None
        data_type = "text"
        if self.loaded_file:
            try:
                with open(self.loaded_file, 'rb') as f:
                    data_to_hide = f.read()
                data_type = "file"
                self.status_var.set(f"🔄 Preparing to hide file: {os.path.basename(self.loaded_file)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {str(e)}")
                return
        else:
            message = self.message_box.get("1.0", tk.END).strip()
            if not message:
                messagebox.showerror("Error", "Please enter a message or upload a file to hide!")
                return
            data_to_hide = message.encode('utf-8')

        img = Image.open(self.loaded_image)
        capacity = (img.width * img.height * 3) // 8
        data_size = len(data_to_hide)
        if data_size > capacity:
            messagebox.showerror("Error", f"Data too large! Max ~{capacity} bytes, yours is {data_size} bytes.")
            img.close()
            return
        img.close()

        password = self.password_field.get().strip()
        try:
            image_to_use = self.convert_to_png(self.loaded_image)
            self.status_var.set("🔄 Hiding data... Please wait.")
            self.root.update()
            secret_data = self.encrypt_data(data_to_hide, password)
            stego_img = lsb.hide(image_to_use, secret_data)
            output_file = f"encoded_{os.path.basename(self.loaded_image).rsplit('.', 1)[0]}.png"
            stego_img.save(output_file)
            self.status_var.set(f"✅ Data hidden! Saved as {output_file}")
            if self.temp_png and os.path.exists(self.temp_png):
                os.remove(self.temp_png)
                self.temp_png = None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data: {str(e)}")

    def reveal_message(self):
        if not self.loaded_image:
            messagebox.showerror("Error", "Please drop a stego-image to decode!")
            return
        if not self.loaded_image.lower().endswith('.png'):
            messagebox.showerror("Error", "Decoding only works with PNG files!")
            return
        password = self.password_field.get().strip()
        try:
            self.status_var.set("🔍 Revealing data... Please wait.")
            self.root.update()
            hidden_data = lsb.reveal(self.loaded_image)
            if hidden_data is None:
                raise ValueError("No hidden data found in the image!")
            data = self.decrypt_data(hidden_data, password)
            self.message_box.delete("1.0", tk.END)
            try:
                # Try decoding as text
                text_data = data.decode('utf-8')
                self.message_box.insert(tk.END, text_data)
                self.status_var.set("✅ Text revealed successfully!")
            except:
                # Save as file if not text
                output_file = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("All files", "*.*")])
                if output_file:
                    with open(output_file, 'wb') as f:
                        f.write(data)
                    self.status_var.set(f"✅ File saved as {output_file}")
                else:
                    self.status_var.set("⚠️ File reveal canceled")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reveal data: {str(e)}")

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = StegoApp(root)
    root.mainloop()
