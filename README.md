# Steganography-App
Steg-go is a Python app that hides secret messages or files inside images using LSB steganography. With a drag-and-drop GUI and optional AES encryption, it lets users securely embed and extract hidden data from PNG, JPG, or BMP images with ease.
Perfect! Since your project has **only one Python file** and you're going for a clean, human-written README, here's a complete and structured `README.md` tailored just for your **Steg-go** project:

---

# 🖼️ Steg-go

**A lightweight Python app to hide secret messages or files inside images using steganography.**

---

## 📌 Overview

**Steg-go** is a simple yet powerful steganography tool built entirely in Python. It lets you securely **embed secret text or entire files inside images** using **Least Significant Bit (LSB)** encoding. With a drag-and-drop interface and optional **AES encryption**, it's perfect for anyone curious about data hiding, cybersecurity, or digital privacy.

---

## 🚀 Features

* 🔐 Hide messages or files inside images
* 🖱️ Drag-and-drop support for easy use
* 🔒 AES encryption with optional password protection
* 🖼️ Works with PNG, JPG, and BMP image formats
* 🧪 Extract and decrypt hidden data from stego-images
* 🧩 All-in-one Python script (no extra setup needed)

---

## 📁 Project Structure

```
Steg-go/
│
├── steg_go.py        # Main and only Python script
├── README.md         # Project documentation
```

---

## ⚙️ Requirements

* Python 3.x
* [Pillow](https://pypi.org/project/Pillow/)
* [TkinterDnD2](https://pypi.org/project/tkinterdnd2/)
* [pycryptodome](https://pypi.org/project/pycryptodome/)

Install dependencies using:

```bash
pip install pillow tkinterdnd2 pycryptodome
```

---

## 🧠 How It Works

1. Drag and drop an image into the app.
2. Enter a message or upload a file to hide.
3. (Optional) Set a password for AES encryption.
4. Save the stego image.
5. To extract, drag the stego image back and enter your password (if any).

---

## 📸 Supported Image Formats

* PNG (best for lossless encoding)
* BMP
* JPG (auto-converted to PNG for compatibility)

---

## 🛡️ Use Cases

* Hide private notes or credentials
* Stealthy file sharing
* Educational projects on steganography
* Digital watermarking practice

---

## 👤 Author

**Fatema Ansari**
🔒 Passionate about cybersecurity, steganography, and building secure tools.

---
