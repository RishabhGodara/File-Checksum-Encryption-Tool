# File-Checksum-Encryption-Tool

A desktop application built using CustomTkinter for calculating file checksums (MD5, SHA-2) and performing AES encryption and decryption on files. This tool helps ensure file integrity and provides data security.

## Features

- Calculate MD5 and SHA-2 checksums for files
- Encrypt files using AES encryption
- Decrypt AES-encrypted files

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/<username>/File-Checksum-Encryption-Tool.git
    ```

2. Navigate to the project directory:
    ```sh
    cd File-Checksum-Encryption-Tool
    ```

3. Install the required dependencies:
    ```sh
    pip install -r requirement.txt
    ```

## Usage

1. Run the application:
    
    python main.py
    

2. Follow the on-screen instructions to select files, calculate checksums, and perform encryption/decryption.

## Dependencies

- customtkinter
- pycryptodome

## File Structure

- `main.py`: The main application file
- `aes.py`: Contains the AES encryption and decryption functions
- `requirement.txt`: Lists the dependencies required for the project

## Contributing

Contributions are welcome! Please create an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
