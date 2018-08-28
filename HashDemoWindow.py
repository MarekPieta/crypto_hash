from PyQt5.QtWidgets import QWidget, QPushButton, QLineEdit, QLabel, QHBoxLayout, QVBoxLayout, QGridLayout, QMessageBox, \
    QPlainTextEdit, QComboBox, QFileDialog
import hashlib
from PyQt5.QtGui import QFont


class HashDemoWindow(QWidget):

    def __init__(self):
        super().__init__()
        self.create_window()

    def create_window(self):
        self.setGeometry(300, 300, 600, 300) #x, y, w, h
        self.setWindowTitle('Hash Demo window')

        self.main_layout = QVBoxLayout(self)

        self.main_description = QLabel('Hash Demo: ', self)
        self.main_description_font = QFont()
        self.main_description_font.setPixelSize(16)
        self.main_description_font.setBold(True)

        self.main_description.setFont(self.main_description_font)
        self.main_layout.addWidget(self.main_description)

        self.hash_layout = QHBoxLayout(self)
        self.main_layout.addLayout(self.hash_layout)

        self.create_string_hash_layout()
        self.create_file_hash_layout()

        self.show()

    def create_string_hash_layout(self):
        self.string_hash_layout = QVBoxLayout(self)
        self.hash_layout.addLayout(self.string_hash_layout)

        self.string_to_hash_info = QLabel('Text to hash: ', self)
        self.string_hash_layout.addWidget(self.string_to_hash_info)
        self.string_to_hash_field = QPlainTextEdit("You can write text here.\n", self)
        self.string_hash_layout.addWidget(self.string_to_hash_field)
        self.string_to_hash_field.textChanged.connect(self.calculate_string_hash_trigger)

        self.string_hash_algorithm_layout = QHBoxLayout(self)
        self.string_hash_layout.addLayout(self.string_hash_algorithm_layout)

        self.string_hash_algorithm_info = QLabel('Text hash algorithm: ', self)
        self.string_hash_algorithm_field = QComboBox(self)
        self.string_hash_algorithm_field.addItem('SHA1')
        self.string_hash_algorithm_field.addItem('SHA224')
        self.string_hash_algorithm_field.addItem('SHA256')
        self.string_hash_algorithm_field.addItem('SHA384')
        self.string_hash_algorithm_field.addItem('SHA512')
        self.string_hash_algorithm_field.addItem('MD5')
        self.string_hash_algorithm_field.currentIndexChanged.connect(self.calculate_string_hash_trigger)

        self.string_hash_algorithm_layout.addWidget(self.string_hash_algorithm_info)
        self.string_hash_algorithm_layout.addWidget(self.string_hash_algorithm_field)

        self.string_hash_result_info = QLabel('Text Hash: ', self)
        self.string_hash_layout.addWidget(self.string_hash_result_info)
        self.string_hash_result_field = QPlainTextEdit(self)
        self.string_hash_result_field.setReadOnly(True)
        self.string_hash_layout.addWidget(self.string_hash_result_field)


    def create_file_hash_layout(self):
        self.file_hash_layout = QVBoxLayout(self)
        self.hash_layout.addLayout(self.file_hash_layout)
        self.file_select_label = QLabel('File to hash: ', self)
        self.file_hash_layout.addWidget(self.file_select_label)

        self.file_select_layout = QHBoxLayout(self)
        self.file_hash_layout.addLayout(self.file_select_layout)

        self.file_select_field = QLineEdit(self)
        self.file_select_field.setReadOnly(True)
        self.file_select_button = QPushButton('Browse files:', self)
        self.file_select_layout.addWidget(self.file_select_field)
        self.file_select_layout.addWidget(self.file_select_button)
        self.file_select_button.clicked.connect(self.get_file_trigger)

        self.file_hash_algorithm_layout = QHBoxLayout(self)
        self.file_hash_layout.addLayout(self.file_hash_algorithm_layout)

        self.file_hash_algorithm_info = QLabel('File hash algorithm: ', self)
        self.file_hash_algorithm_field = QComboBox(self)
        self.file_hash_algorithm_field.addItem('SHA1')
        self.file_hash_algorithm_field.addItem('SHA224')
        self.file_hash_algorithm_field.addItem('SHA256')
        self.file_hash_algorithm_field.addItem('SHA384')
        self.file_hash_algorithm_field.addItem('SHA512')
        self.file_hash_algorithm_field.addItem('MD5')
        self.file_hash_algorithm_layout.addWidget(self.file_hash_algorithm_info)
        self.file_hash_algorithm_layout.addWidget(self.file_hash_algorithm_field)
        self.file_hash_algorithm_field.currentIndexChanged.connect(self.change_file_hash_algorithm_trigger)


        self.file_hash_result_info = QLabel('File hash: ', self)
        self.file_hash_layout.addWidget(self.file_hash_result_info)

        self.file_hash_result_field = QPlainTextEdit(self)
        self.file_hash_result_field.setReadOnly(True)
        self.file_hash_layout.addWidget(self.file_hash_result_field)

    def calculate_string_hash_trigger(self):
        text = self.string_to_hash_field.toPlainText()
        hash_algorithm = self.string_hash_algorithm_field.currentText()
        hash = self.calculate_hash(hash_algorithm, text)
        self.string_hash_result_field.setPlainText(hash)

    def calculate_hash(self, hash_algorithm, text):
        if hash_algorithm == 'SHA1':
            m = hashlib.sha1()

        if hash_algorithm == 'SHA224':
            m = hashlib.sha224()

        if hash_algorithm == 'SHA256':
            m = hashlib.sha256()

        if hash_algorithm == 'SHA384':
            m = hashlib.sha384()

        if hash_algorithm == 'SHA512':
            m = hashlib.sha512()

        if hash_algorithm == 'MD5':
            m = hashlib.md5()

        m.update(text.encode())
        return m.hexdigest()

    def get_file_trigger(self):
        fname = QFileDialog.getOpenFileName(self)
        if fname == ('', ''):
            return
        self.file_select_field.setText(fname[0])
        hash_algorithm = self.file_hash_algorithm_field.currentText()
        self.file_hash_result_field.setPlainText(self.calculate_hash_over_file(hash_algorithm, fname[0]))

    def change_file_hash_algorithm_trigger(self):
        fname = self.file_select_field.text()
        if fname == '':
            return
        hash_algorithm = self.file_hash_algorithm_field.currentText()
        self.file_hash_result_field.setPlainText(self.calculate_hash_over_file(hash_algorithm, fname))


    def calculate_hash_over_file(self, hash_algorithm, filename):
        if hash_algorithm == 'SHA1':
            m = hashlib.sha1()

        if hash_algorithm == 'SHA224':
            m = hashlib.sha224()

        if hash_algorithm == 'SHA256':
            m = hashlib.sha256()

        if hash_algorithm == 'SHA384':
            m = hashlib.sha384()

        if hash_algorithm == 'SHA512':
            m = hashlib.sha512()

        if hash_algorithm == 'MD5':
            m = hashlib.md5()

        CHUNK_SIZE = 65536
        with open(filename, 'rb') as f:
            while True:
                data = f.read(CHUNK_SIZE)
                if not data:
                    break
                m.update(data)

        return m.hexdigest()
