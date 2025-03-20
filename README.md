# PGP Protection Project

## Project Overview  
This project is a **PGP (Pretty Good Privacy) encryption** application built in **Python** with a **PyQt** GUI. The application enables users to send and receive messages with full support for all PGP functionalities, including:

- **Confidentiality** – Ensures the message is readable only by the intended recipient.
- **Authenticity** – Verifies that the sender is who they claim to be.
- **Compression** – Compresses the message to save bandwidth.
- **Email Compatibility** – Uses radix64 encoding to ensure compatibility with email systems.
- **Asymmetric Key Encryption** – Uses public and private keys for encryption and digital signatures.
- **Symmetric Key Encryption** – Uses a shared secret key for encryption.

The application also implements **public and private key rings** for storing keys and managing encryption processes.

## Features  
The user interacts with the application through a GUI, where they can select different functionalities for their message, including:

- **Digital Signing**
- **Message Encryption**
- **Compression**

The selected functionalities create a header for each message, which is then analyzed upon receipt. By analyzing the header, the application determines which functionalities were used and handles the necessary steps to properly decrypt and verify the message.

## Key Functionalities  
- **Message Signing**: Users can sign messages to ensure their authenticity.
- **Message Encryption**: Encrypts messages to maintain confidentiality.
- **Message Compression**: Compresses the message content to reduce the size.
- **Key Rings**: A structure that manages public and private keys for signing and encryption.
- **Radix64 Encoding**: Ensures email compatibility by converting messages into a format suitable for email transmission.

## Team  
This project was developed as a team effort by my friend and me.

## Installation  
1. Clone the repository:
    ```bash
    git clone https://github.com/TeodoraRistovic13/pgp-email-protection.git
    ```
2. Install the required Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the application:
    ```bash
    python gui.py
    ```

## Technologies Used  
- **Python**  
- **PyQt** (for the GUI)
- **PGP encryption standards**

## Team Collaboration  
This project is developed as a team effort. The contributor is:  
- [@User1](https://github.com/scurovic)
