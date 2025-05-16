# NetCrypt

NetCrypt is a lightweight VPN application that encrypts all your data traffic with AES-256. With NetCrypt, your internet connection is protected from threats such as hacking and tracking, ensuring your online activities remain safe and private.

## Installation

Clone the repository by running the following command:

```shell
git clone https://github.com/Superior231/NetCrypt.git
```

Make sure you have created a Virtual Environment before. Run the following command to create a Virtual Environment:

```shell
python -m venv venv
venv\Scripts\activate
```

After creating a Virtual Environment, you can install the required libraries by running the following command:

```shell
pip install -r requirements.txt
```

## Usage

Run the following command to start the server:

```shell
python app.py
```

Server is running. Open url `http://127.0.0.1:5000/` in browser.

## How It Works?

NetCrypt uses AES-256 encryption to encrypt your data traffic. It uses a symmetric key to encrypt and decrypt data, making it impossible for others to access your data.

1. Create an account with username and password
2. Choose a server location
3. Download your personalized `.ovpn` configuration file
4. Connect using OpenVPN with your credentials. You can install OpenVPN on your device as follows:
   - Windows: [OpenVPN Community](https://openvpn.net/community-downloads/)
   - Mac: [Tunnelblick](https://tunnelblick.net/)
   - Linux: `sudo apt-get install openvpn` (Ubuntu/Debian)
   - Android: [OpenVPN Connect](https://play.google.com/store/apps/details?id=net.openvpn.openvpn)
   - iOS: [OpenVPN Connect](https://apps.apple.com/us/app/openvpn-connect/id590379981)
5. Enjoy a secure and private internet connection

## Progressive Web App (PWA) Support✅

NetCrypt comes with full Progressive Web App (PWA) support, delivering a faster, more reliable, and engaging user experience.

Key PWA Features in NetCrypt:
- **Easy Installation**: Users can install NetCrypt directly from their browser to their device, just like a native app.
- **Fast Loading**: Intelligent caching enables quicker load times and reduced data usage.
- **Cross-Platform**: Works seamlessly on both desktop and mobile devices without needing app store downloads.

With PWA technology, NetCrypt bridges the best of web and native apps, ensuring accessibility and performance wherever you are.