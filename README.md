# RSA_Helper

## Version: 1.0.0  
**Release Date:** `2024-09`  

### Description

`RSA Viewer` is a PyQt5-based application designed to simplify the visualization and handling of RSA keys. It provides an intuitive UI to manage key files, perform encryption and decryption, and explore different encryption algorithms. The application supports both `.key` and `.enc` file formats, offering drag-and-drop functionality for enhanced user experience.

---

### Features

- **Tabbed Interface**: The application contains three main tabs:
  - **Welcome**: A friendly welcome screen with branding elements and a `Continue` button to navigate to the RSA Editor.
  - **RSA Editor**: A fully functional editor where users can explore RSA key files and perform encryption and decryption.
  - **Algorithm**: A section displaying encryption and decryption logic in multiple languages (Java and Python).

- **File Explorer**: 
  - The editor provides an explorer widget to navigate through RSA key files and `.enc` files. 
  - Supports opening files with a double-click event.

- **Password Protection**: 
  - A secure interface to input, change, and toggle password visibility for decryption.

- **Key Pair Generation**: 
  - Users can create new key pairs directly in the RSA editor tab.

- **Tooltips and Styling**: 
  - Tooltips enhance usability by providing context-sensitive help for buttons and features.
  - Custom stylesheets give the app a polished look, including gradient backgrounds and smooth button hover effects.

---

### Key Components

1. **Welcome Tab**:
   - Displays a welcome image and a welcome message.
   - Includes a `CONTINUE` button to proceed to the RSA Editor.

2. **RSA Editor Tab**:
   - **File Explorer**: Allows users to navigate and open key files (`*.key`, `*.enc`).
   - **Editor Section**: Displays the content of selected files, with options to save, create new keys, and modify passwords.
   - **Password Handling**: A secure password input area with a visibility toggle button and a password change option.

3. **Algorithm Tab**:
   - Shows the data encryption and decryption logic for both Java and Python.
   - Users can switch between languages to view corresponding encryption logic.

---

### UI Customization

- **Stylesheets**: 
  - Custom styles for tooltips, buttons, and background gradients provide a modern look.
  - Tab design includes a triangular shape and west-aligned tab positioning for better usability.
  
- **Responsive Layouts**: 
  - The application adapts to window resizing and enforces minimum size constraints for a consistent UI experience.

---

### Getting Started

1. **Install Dependencies**:
   - Install the required dependencies using the following command:
     ```bash
     pip install PyQt5
     ```

2. **Run the Application**:
   - Execute the main Python script to launch the `RSA Viewer`:
     ```bash
     python MainWindow.py
     ```

3. **Using the Application**:
   - Explore the tabs and load RSA key files from the `Explorer` tab.
   - Use the editor to modify or view key details, create new key pairs, and manage passwords.

---

### Screenshots

*Include some screenshots of the application here for better visual understanding.*

---

### Future Enhancements

- **More Encryption Algorithms**: Support for additional encryption algorithms like AES and DES.
- **Improved Key Management**: Enhanced key file management features.
- **Dark Mode**: The application will soon include a dark mode for users preferring a darker UI.

---

**Contact**: For further information or support, feel free to reach out via [LinkedIn](https://www.linkedin.com/in/sunit-mal/).

---
