import sys, os, logging
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QFileSystemModel,
    QTreeView,
    QTextEdit,
    QGridLayout,
    QMessageBox,
    QToolBox,
    QLineEdit,
    QToolTip,
    QDialog,
    QFormLayout,
    QDialogButtonBox,
    QHBoxLayout,
    QFileDialog,
    QStackedWidget,
)
from PyQt5.QtCore import Qt, pyqtSlot, QModelIndex
from PyQt5.QtGui import QIcon, QFont, QPixmap, QFontDatabase
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from _internal.KeyFileGenerator import KeyFileGenerator

logging.basicConfig(
    filename=os.path.join("_internal", "app.log"),
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        app = QApplication.instance()
        if not app:
            app = QApplication(sys.argv)

        app.setStyleSheet(
            """
            QToolTip {
                color: black;
                background-color: white;
                border: 1px solid yellow;
                padding: 5px;
                font-size: 12px;
                border-radius: 5px;
            }
        """
        )

        self.title = "RSA Viewer"
        self.left = 150
        self.top = 200
        self.width = 1200
        self.height = 750
        self.file_name = None
        self.decrypt_password = "Demo@123"
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setMinimumSize(self.width, self.height)

        self.setWindowIcon(QIcon(os.path.join("_internal", "icon.png")))

        QToolTip.setFont(QFont("Times New Roman", 12))

        self.main_layout = QVBoxLayout()

        self.welcome_widget = QWidget()
        self.rsa_editor = QWidget()
        self.algorithm = QWidget()

        self.initialization_tabs()
        self.welcome_layout()
        self.editor_layout()
        self.algorithm_layout()

        self.show()
        self.style_sheet_add()

    def initialization_tabs(self):
        # Make Tab
        self.tabs = QTabWidget()
        self.tabs.addTab(self.welcome_widget, "Welcome")
        self.tabs.addTab(self.rsa_editor, "RSA Editor")
        self.tabs.addTab(self.algorithm, "Algorithm")
        self.tabs.setTabPosition(QTabWidget.West)
        self.tabs.setTabShape(QTabWidget.Triangular)
        self.tabs.setAcceptDrops(True)
        self.tabs.setGeometry(0, 0, self.width, self.height)

        self.main_layout.addWidget(self.tabs)
        self.setLayout(self.main_layout)

    def welcome_layout(self):
        self.welcome_layout = QVBoxLayout()
        self.welcome_widget.setLayout(self.welcome_layout)

        self.welcome_image = QLabel()
        self.welcome_image.setPixmap(QPixmap((os.path.join("_internal", "icon.png"))))
        self.welcome_image.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.welcome_image.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.welcome_layout.addWidget(self.welcome_image)

        self.welcome_label = QLabel("Welcome to RSA Viewer")
        self.welcome_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.welcome_label.setFont(QFont("Times New Roman", 30, QFont.Bold, True))
        self.welcome_label.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.welcome_layout.addWidget(self.welcome_label)

        self.welcome_button_layout = QVBoxLayout()
        self.welcome_button_layout.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.welcome_continue_button = QPushButton("CONTINUE")
        self.welcome_continue_button.setToolTip("Continue to the RSA Editor")
        self.welcome_continue_button.setFont(QFont("Times New Roman", 15, QFont.Bold))
        self.welcome_continue_button.setMaximumWidth(int(self.width / 3))
        self.welcome_continue_button.setMinimumWidth(int(self.width / 3))
        self.welcome_continue_button.clicked.connect(
            lambda: self.tabs.setCurrentIndex(1)
        )
        self.welcome_button_layout.addWidget(self.welcome_continue_button)
        self.welcome_layout.addLayout(self.welcome_button_layout)

    def editor_layout(self):
        self.editor_layout = QVBoxLayout()
        self.rsa_editor.setLayout(self.editor_layout)

        self.file_explorer_widget = QWidget()
        self.file_explorer_layout = QVBoxLayout()
        self.explorer()

        self.file_editor_widget = QWidget()
        self.editor()
        self.file_editor_widget.setLayout(self.editor_frame)

        self.file_explorer_widget.setLayout(self.file_explorer_layout)

        self.editor_toolBox = QToolBox()
        self.editor_toolBox.addItem(self.file_explorer_widget, "EXPLORER")
        self.editor_toolBox.addItem(self.file_editor_widget, "EDITOR")
        self.editor_toolBox.setFont(QFont("Times New Roman", 12))

        self.editor_layout.addWidget(self.editor_toolBox)

    def explorer(self):
        self.explorer_model = QFileSystemModel()
        self.explorer_model.setRootPath("")
        self.explorer_model.setNameFilters(["*.key", "*.enc"])
        self.explorer_model.setNameFilterDisables(False)
        self.explorer_tree = QTreeView()
        self.explorer_tree.setModel(self.explorer_model)
        self.explorer_tree.setAnimated(True)
        self.explorer_tree.setIndentation(20)
        self.explorer_tree.setSortingEnabled(True)
        self.explorer_tree.doubleClicked.connect(self.read_file)
        self.file_explorer_layout.addWidget(self.explorer_tree)

    def editor(self):
        self.label_file_title = QLabel()
        self.label_file_title.setGeometry(0, 0, self.width, 10)
        self.label_file_title.setFont(QFont("Times New Roman", 11))
        self.label_file_title.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.textbox = QTextEdit()
        self.textbox.setLineWrapMode(QTextEdit.WidgetWidth)
        self.textbox.setFont(QFont("Times New Roman", 10))
        self.textbox.setStyleSheet(
            """
                background-color: aliceblue;
                border: none;
                border-radius: 5px;
                padding: 5px;
            """
        )

        self.editor_frame = QGridLayout()
        self.editor_frame.addWidget(self.label_file_title, 0, 0, 1, 4)
        self.editor_frame.addWidget(self.textbox, 1, 0, 3, 4)

        self.editor_frame_button_widget = QWidget()
        self.editor_frame_button = QGridLayout()
        self.editor_frame_button_widget.setLayout(self.editor_frame_button)

        self.save_button = QPushButton("Save")
        self.save_button.setToolTip("Save the file")
        self.save_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.save_button.setFont(QFont("Times New Roman", 12))
        self.save_button.clicked.connect(self.save_file)
        self.editor_frame_button.addWidget(self.save_button, 0, 0)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setToolTip("Go back")
        self.cancel_button.setStyleSheet("background-color: #f44336; color: white;")
        self.cancel_button.setFont(QFont("Times New Roman", 12))
        self.cancel_button.clicked.connect(
            lambda: self.editor_toolBox.setCurrentIndex(0)
        )
        self.editor_frame_button.addWidget(self.cancel_button, 0, 1)

        self.new_button = QPushButton("New")
        self.new_button.setToolTip("Create a new file")
        self.new_button.setStyleSheet("background-color: #008CBA; color: white;")
        self.new_button.setFont(QFont("Times New Roman", 12))
        self.new_button.clicked.connect(self.create_new_key_pair)
        self.editor_frame_button.addWidget(self.new_button, 0, 2)

        self.password_widget = QWidget()
        self.password_layout = QGridLayout()
        self.password_label = QLabel("Password : ")
        self.password_label.setFont(QFont("Times New Roman", 12))
        self.password_layout.addWidget(self.password_label, 0, 0)

        self.password_input_widget = QWidget()
        self.password_input_layout = QHBoxLayout()
        self.password = QLineEdit()
        self.password.setText(self.decrypt_password)

        self.password.setMinimumWidth(int(self.width / 4))

        self.password.setFont(QFont("Times New Roman", 12))
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setStyleSheet(
            """
                background-color: aliceblue;
                border: none;
                border-radius: 5px;
                padding: 5px;
            """
        )
        self.password_input_layout.addWidget(self.password)
        self.password_input_widget.setLayout(self.password_input_layout)
        self.password_form_layout = QFormLayout()

        self.password_button_widget = QWidget()
        self.password_button_layout = QHBoxLayout()
        self.hide_button = QPushButton()
        self.hide_button.setIcon(QIcon((os.path.join("_internal", "hide.png"))))
        self.hide_button.setFixedSize(30, 30)
        self.hide_button.clicked.connect(self.toggle_password_visibility)
        self.password_button_layout.addWidget(self.hide_button)
        self.password_button_widget.setLayout(self.password_button_layout)
        self.password_form_layout.addRow(
            self.password_input_widget, self.password_button_widget
        )

        self.password_and_button_widget = QWidget()
        self.password_and_button_widget.setLayout(self.password_form_layout)
        self.password_layout.addWidget(self.password_and_button_widget, 0, 1, 1, 5)

        self.change_button = QPushButton("Change")
        self.change_button.setToolTip("Change the password")
        self.change_button.setStyleSheet("background-color: #6ca7a1; color: white;")
        self.change_button.setFont(QFont("Times New Roman", 12))
        self.change_button.clicked.connect(self.change_password)
        self.password_layout.addWidget(self.change_button, 1, 5)

        self.password_widget.setLayout(self.password_layout)
        self.editor_frame_button.addWidget(self.password_widget, 0, 3)
        self.editor_frame_button_widget.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0);"
        )

        self.button_widget = QWidget()
        self.button_widget.setLayout(self.editor_frame_button)
        self.button_widget.setStyleSheet("background-color: rgba(255, 255, 255, 0);")

        self.editor_frame.addWidget(self.button_widget, 4, 0, 1, 4)

    def toggle_password_visibility(self):
        if self.password.echoMode() == QLineEdit.Password:
            self.password.setEchoMode(QLineEdit.Normal)
            self.hide_button.setIcon(QIcon((os.path.join("_internal", "view.png"))))
        else:
            self.password.setEchoMode(QLineEdit.Password)
            self.hide_button.setIcon(QIcon((os.path.join("_internal", "hide.png"))))

    def style_sheet_add(self):
        self.setStyleSheet(
            """
            font-family: 'Times New Roman';
            background: qlineargradient(
                x1: 0, y1: 0,
                x2: 0, y2: 1,
                stop: 0 #a8edea,
                stop: 1 #fed6e3
            );
            QToolTip {
                color: black !important;
            }
            """
        )

        self.welcome_continue_button.setStyleSheet(
            """
                QPushButton{
                    border-radius: 5px;
                    padding-top: 5px;
                    padding-bottom: 5px;
                    background: qlineargradient(
                        x1: 0, y1: 0,
                        x2: 1, y2: 0,
                        stop: 0 #16222b,
                        stop: 1 #3a5f72
                    );
                    color:white;
                }

                QPushButton:hover{
                    background: qlineargradient(
                        x1: 1, y1: 0,
                        x2: 0, y2: 0,
                        stop: 0 #16222b,
                        stop: 1 #3a5f72
                    );
                }
            """
        )

    def algorithm_layout(self):
        self.algorithm_layout = QVBoxLayout()

        self.algorithm.setLayout(self.algorithm_layout)

        self.algorithm_tab_toolbox = QToolBox()
        self.algorithm_tab_toolbox.setFont(QFont("Times New Roman", 12))

        self.encryption_widget = QWidget()
        self.encryption_widget_layout = QVBoxLayout(self.encryption_widget)

        self.decryption_widget = QWidget()
        self.decryption_widget_layout = QVBoxLayout(self.decryption_widget)

        self.algorithm_tab_toolbox.addItem(
            self.encryption_widget, "Data Encryption logic"
        )
        self.algorithm_tab_toolbox.addItem(self.decryption_widget, "Data Decryption logic")

        self.algorithm_encryption_stack = QStackedWidget()

        self.algo_java_page = QWidget()
        self.algo_java_page_layout = QVBoxLayout(self.algo_java_page)
        self.algo_java_page_text = QTextEdit()
        self.algo_java_page_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.algo_java_page_text.setReadOnly(True)
        self.algo_java_page_text.setFont(QFont("Times New Roman", 12))

        self.algo_java_page_text.setText(
            self.read_file_insert("_internal/dataEncryption.java")
        )
        self.algo_java_page_layout.addWidget(self.algo_java_page_text)
        self.algo_java_page_text.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0);border: none;"
        )

        self.algo_py_page = QWidget()
        self.algo_py_page_layout = QVBoxLayout(self.algo_py_page)
        self.algo_py_page_text = QTextEdit("Python Encryption Logic")
        self.algo_py_page_text.setFont(QFont("Times New Roman", 12))
        self.algo_py_page_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.algo_py_page_text.setReadOnly(True)

        self.algo_py_page_text.setText(
            self.read_file_insert("_internal/dataEncryption.py")
        )
        self.algo_py_page_layout.addWidget(self.algo_py_page_text)
        self.algo_py_page_text.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0);border: none;"
        )

        self.algorithm_encryption_stack.addWidget(self.algo_java_page)
        self.algorithm_encryption_stack.addWidget(self.algo_py_page)

        self.encryption_widget_layout.addWidget(self.algorithm_encryption_stack)

        self.switch_button_widget = QWidget()
        self.switch_button_widget.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0);border: none;"
        )
        self.switch_button_layout = QVBoxLayout()
        self.switch_button = QPushButton()
        self.switch_button.setText("Change Language")
        self.switch_button.setIcon(QIcon(os.path.join("_internal", "switch.png")))
        self.switch_button.setFont(QFont("Times New Roman", 12))
        self.switch_button.setMinimumWidth(180)
        self.switch_button.setMinimumHeight(30)
        self.switch_button.setMaximumWidth(180)
        self.switch_button.setMaximumHeight(30)
        self.switch_button.setLayoutDirection(Qt.RightToLeft)
        self.switch_button.setStyleSheet(
            """
                QPushButton{
                    border-radius: 5px;
                    padding-top: 5px;
                    padding-bottom: 5px;
                    background-color: aliceblue;
                    color:black;
                }
            """
        )
        self.switch_button.clicked.connect(self.switch_stack_page)
        self.switch_button_layout.addWidget(self.switch_button)
        self.switch_button_widget.setLayout(self.switch_button_layout)
        self.encryption_widget_layout.addWidget(self.switch_button_widget)

        self.algorithm_decryption_stack = QStackedWidget()

        self.algo_java_decryption_page = QWidget()
        self.algo_java_decryption_page_layout = QVBoxLayout(self.algo_java_decryption_page)
        self.algo_java_decryption_page_text = QTextEdit()
        self.algo_java_decryption_page_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.algo_java_decryption_page_text.setReadOnly(True)
        self.algo_java_decryption_page_text.setFont(QFont("Times New Roman", 12))

        self.algo_java_decryption_page_text.setText(
            self.read_file_insert("_internal/dataDecryption.java")
        )
        self.algo_java_decryption_page_layout.addWidget(self.algo_java_decryption_page_text)
        self.algo_java_decryption_page_text.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0);border: none;"
        )

        self.algo_py_decryption_page = QWidget()
        self.algo_py_decryption_page_layout = QVBoxLayout(self.algo_py_decryption_page)
        self.algo_py_decryption_page_text = QTextEdit("Python decryption Logic")
        self.algo_py_decryption_page_text.setFont(QFont("Times New Roman", 12))
        self.algo_py_decryption_page_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.algo_py_decryption_page_text.setReadOnly(True)

        self.algo_py_decryption_page_text.setText(
            self.read_file_insert("_internal/dataDecryption.py")
        )
        self.algo_py_decryption_page_layout.addWidget(self.algo_py_decryption_page_text)
        self.algo_py_decryption_page_text.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0);border: none;"
        )

        self.algorithm_decryption_stack.addWidget(self.algo_java_decryption_page)
        self.algorithm_decryption_stack.addWidget(self.algo_py_decryption_page)

        self.decryption_widget_layout.addWidget(self.algorithm_decryption_stack)

        self.switch_button_decryption_widget = QWidget()
        self.switch_button_decryption_widget.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0);border: none;"
        )
        self.switch_button_decryption_layout = QVBoxLayout()
        self.switch_button_decryption = QPushButton()
        self.switch_button_decryption.setText("Change Language")
        self.switch_button_decryption.setIcon(QIcon(os.path.join("_internal", "switch.png")))
        self.switch_button_decryption.setFont(QFont("Times New Roman", 12))
        self.switch_button_decryption.setMinimumWidth(180)
        self.switch_button_decryption.setMinimumHeight(30)
        self.switch_button_decryption.setMaximumWidth(180)
        self.switch_button_decryption.setMaximumHeight(30)
        self.switch_button_decryption.setLayoutDirection(Qt.RightToLeft)
        self.switch_button_decryption.setStyleSheet(
            """
                QPushButton{
                    border-radius: 5px;
                    padding-top: 5px;
                    padding-bottom: 5px;
                    background-color: aliceblue;
                    color:black;
                }
            """
        )
        self.switch_button_decryption.clicked.connect(self.decrypt_switch_stack_page)
        self.switch_button_decryption_layout.addWidget(self.switch_button_decryption)
        self.switch_button_decryption_widget.setLayout(self.switch_button_decryption_layout)
        self.decryption_widget_layout.addWidget(self.switch_button_decryption_widget)

        self.algorithm_layout.addWidget(self.algorithm_tab_toolbox)

    def switch_stack_page(self):
        current_index = self.algorithm_encryption_stack.currentIndex()
        next_index = (current_index + 1) % self.algorithm_encryption_stack.count()
        self.algorithm_encryption_stack.setCurrentIndex(next_index)
    
    def decrypt_switch_stack_page(self):
        current_index = self.algorithm_decryption_stack.currentIndex()
        next_index = (current_index + 1) % self.algorithm_decryption_stack.count()
        self.algorithm_decryption_stack.setCurrentIndex(next_index)

    # Execution Functions
    @pyqtSlot()
    def read_file_insert(self, file_path):
        try:
            with open(file_path, "r") as file:
                return file.read()
        except Exception as e:
            QMessageBox.critical(self, "Error", "Something went wrong")
            logging.error("Error occurred during read_file: %s", e, exc_info=True)
            return ""

    @pyqtSlot(QModelIndex)
    def read_file(self, index):
        self.file_path = self.explorer_model.fileInfo(index).absoluteFilePath()
        self.file_name = self.explorer_model.fileName(index)
        try:
            if self.file_name.endswith(".key"):
                self.label_file_title.setText("File Name : " + self.file_name)
                self.read_key_file()
            elif self.file_name.endswith(".enc"):
                self.label_file_title.setText("File Name : " + self.file_name)
                self.read_enc_file(self.file_path)
            else:
                QMessageBox.information(
                    self, "Information", "This File not open via this tool"
                )
        except Exception as e:
            QMessageBox.critical(self, "Error", "Something went wrong")
            logging.error("Error occurred during read_file: %s", e, exc_info=True)

    @pyqtSlot()
    def read_key_file(self):
        try:
            with open(self.file_path, "r") as file:
                self.textbox.setText(file.read())
                self.editor_toolBox.setCurrentIndex(1)
        except Exception as e:
            QMessageBox.critical(self, "Error", "File Not Supported")
            logging.error("Error occurred during read_key_file: %s", e, exc_info=True)

    @pyqtSlot()
    def show_input_dialog(self):
        dialog = InputDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.decrypt_password = dialog.get_text()
            self.password.setText(self.decrypt_password)
            self.editor_toolBox.setCurrentIndex(1)

    @pyqtSlot()
    def change_password(self):
        self.decrypt_password = self.password.text()
        self.password.setText(self.decrypt_password)
        self.save_file()
        QMessageBox.information(self, "Success", "Password Changed Successfully!")

    @pyqtSlot()
    def read_enc_file(self, file_path):
        self.show_input_dialog()
        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = kdf.derive(self.decrypt_password.encode())

            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            self.content = unpadder.update(padded_data) + unpadder.finalize()
            self.textbox.setText(self.content.decode())
        except Exception as e:
            self.textbox.setText("")
            QMessageBox.critical(self, "Error", "Please Recheck Password")
            logging.error("Error occurred during read_enc_file: %s", e, exc_info=True)

    @pyqtSlot()
    def save_file(self):
        self.store_directory = self.show_directory_dialog()
        if not self.store_directory:
            QMessageBox.information(self, "Information", "Directory not selected")
        else:
            if self.file_name.endswith(".key"):
                file_location = os.path.join(self.store_directory, self.file_name)
                with open(file_location, "w") as file:
                    file.write(self.textbox.toPlainText())
                    QMessageBox.information(self, "Success", "File Saved Successfully!")
            elif self.file_name.endswith(".enc"):
                file_location = os.path.join(self.store_directory, self.file_name)
                self.encrypt_file(file_location)
            else:
                QMessageBox.information(
                    self, "Information", "Please select a file to save"
                )

    @pyqtSlot()
    def encrypt_file(self, store_directory):
        try:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = kdf.derive(self.decrypt_password.encode())

            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = (
                padder.update(self.textbox.toPlainText().encode()) + padder.finalize()
            )
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            with open(store_directory, "wb") as f:
                f.write(salt + iv + encrypted_data)
                QMessageBox.information(self, "Success", "File Encrypted Successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", "Something went wrong")
            logging.error("Error occurred during encrypt_file: %s", e, exc_info=True)

    @pyqtSlot()
    def show_directory_dialog(self):
        dialog = DirectorySelectionDialog(self)
        return dialog.open_directory_dialog()

    @pyqtSlot()
    def create_new_key_pair(self):
        dialog = InputDialog(self)
        password = None
        try:
            if dialog.exec_() == QDialog.Accepted:
                password = dialog.get_text()
            storage_path = self.show_directory_dialog()
            print(password, storage_path)
            if not storage_path:
                QMessageBox.information(self, "Information", "Directory not selected")
            elif not password:
                QMessageBox.information(self, "Information", "Password not entered")
            else:
                KeyFileGenerator.generate_keys(password, storage_path)
                QMessageBox.information(
                    self, "Success", "Key Pair Generated Successfully!"
                )
        except Exception as e:
            QMessageBox.critical(self, "Error", "Something went wrong")
            logging.error(
                "Error occurred during create_new_key_pair: %s", e, exc_info=True
            )


class InputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Required")
        self.setWindowIcon(QIcon((os.path.join("_internal", "icon.png"))))

        # Main Layout
        self.layout = QFormLayout()

        self.input_widget = QWidget()
        self.input_layout = QHBoxLayout()
        self.input_widget.setLayout(self.input_layout)
        self.input_widget.setStyleSheet("background-color: rgba(255, 255, 255, 0);")

        # Password Input Field
        self.input_field = QLineEdit()
        self.input_field.setFont(QFont("Times New Roman", 12))
        self.input_field.setPlaceholderText("Demo@123")
        self.input_field.setEchoMode(QLineEdit.Password)
        self.input_field.setStyleSheet(
            """
                background-color: aliceblue;
                border: none;
                border-radius: 5px;
                padding: 5px;
            """
        )
        self.input_layout.addWidget(self.input_field)

        # Hide/Show Button
        self.hide_button = QPushButton()
        self.hide_button.setIcon(QIcon((os.path.join("_internal", "hide.png"))))
        self.hide_button.setFixedSize(30, 30)
        self.hide_button.clicked.connect(self.toggle_password_visibility)
        self.input_layout.addWidget(self.hide_button)

        self.label_widget = QWidget()
        self.label_layout = QHBoxLayout()
        self.label = QLabel("Enter Password : ")
        self.label_layout.addWidget(self.label)
        self.label_widget.setLayout(self.label_layout)
        self.label_widget.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.label.setFont(QFont("Times New Roman", 12))
        self.layout.addRow(self.label_widget, self.input_widget)

        self.button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)

        self.setLayout(self.layout)

    def toggle_password_visibility(self):
        if self.input_field.echoMode() == QLineEdit.Password:
            self.input_field.setEchoMode(QLineEdit.Normal)
            self.hide_button.setIcon(QIcon((os.path.join("_internal", "view.png"))))
        else:
            self.input_field.setEchoMode(QLineEdit.Password)
            self.hide_button.setIcon(QIcon((os.path.join("_internal", "hide.png"))))

    @pyqtSlot()
    def get_text(self):
        return self.input_field.text()


class DirectorySelectionDialog(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Directory")
        self.setGeometry(100, 100, 400, 200)
        self.setStyleSheet(
            """
                font-family: 'Times New Roman';
                background-color: #f0f0f0;
            """
        )

    def open_directory_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory", "", options=options
        )

        if directory:
            return directory


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_win = MainWindow()
    sys.exit(app.exec_())
