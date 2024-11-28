# Encryption/Decryption Web App

This web application allows users to encrypt and decrypt messages using three popular encryption algorithms: RSA, DSA, and AES. 

## Features
- **Encrypt** and **Decrypt** messages using RSA, DSA, and AES algorithms.
- Simple and easy-to-use web interface.

## Installation

Follow the steps below to set up and run the application:

### 1. Clone the repository
Clone this repository to your local machine using the following command:

```bash
git clone https://github.com/yourusername/your-repository-name.git
```

### 2. Set up dependencies
Execute the batch script to install the necessary dependencies by running:
```bash
./setup.bat
```

### 3. Run the server
Start the development server using the following command:
```bash
npm run dev
```
This will start the server, and you can access the web app by navigating to http://localhost:3000 in your web browser.

## Algorithms Supported
- [**RSA**](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [**DSA**](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
- [**AES**](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

These algorithms can be used for both encryption and decryption within the app.

## Usage

- To **encrypt** a message:
  - Select the encryption algorithm (RSA, DSA, or AES).
  - Input the message to encrypt.
  - Enter the encryption key (if required).
  - Click on the **Encrypt** button to get the encrypted message.

- To **decrypt** a message:
  - Select the decryption algorithm (RSA, DSA, or AES).
  - Input the encrypted message.
  - Enter the decryption key (if required).
  - Click on the **Decrypt** button to get the decrypted message.
