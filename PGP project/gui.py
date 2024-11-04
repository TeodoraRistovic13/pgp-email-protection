import sys
import encryption

from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QLineEdit, \
    QPushButton, QComboBox, QGroupBox, QGridLayout, QHBoxLayout, QListWidget, QFileDialog, \
    QMessageBox, QListWidgetItem, QInputDialog, QTableWidget, QTableWidgetItem, QAction, QCheckBox

from PyQt5.QtCore import Qt, QSize, QStringListModel

import rings
from rings import *
user_id = "tea@gmail.com" # ulogovani korisnik

class PGPApp(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("PGP Email Protection")
        self.setGeometry(100, 100, 800, 600)

        #kreiranje glavnog menia
        #mozda iskoristimo za nesto..
        mainMenu = self.menuBar()
        self.user_menu = mainMenu.addMenu(user_id)
        self.profile_menu = self.user_menu.addMenu("Select Profile")

        #kreiranje tabova
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tab_key_management = QWidget()
        self.tab_send_message = QWidget()
        self.tab_receive_message = QWidget()
        self.tab_key_rings = QWidget()
        self.label_user_id = QLabel(user_id)

        #dodavanje naziva tabovima
        self.tabs.addTab(self.tab_key_management, "Key Management")
        self.tabs.addTab(self.tab_send_message, "Send Message")
        self.tabs.addTab(self.tab_receive_message, "Receive Message")
        self.tabs.addTab(self.tab_key_rings, "Key Rings")

        #lista koja sadrzi sve aktivne kljuceve koji se prikazuju na guiu
        self.gui_key_list = []
        #inputovi na tabu key management
        self.key_management_inputs = {}

        #generise prvih 5 kljuceva
        self.init_data()

        #inicijalizacije tabova

        self.key_management_ui()
        self.key_rings_ui()
        self.send_message_ui()
        self.receive_message_ui()
        
        #ucitava kljuceve u listu za brisanje kljuceva
        self.load_keys_for_delete_list()
        #ucitava tabelu javnih kljuceva u keys ring tab
        self.init_load_key_rings_table()
        #centrira prozor na vrh ekrana
        self.populate_export_combo_box()
        #kao neki login..
        self.load_profile_options()

        self.center()


    #centrira glavni prozor u okviru ekrana
    def center(self):

        screen_geometry = QApplication.desktop().screenGeometry()
        center_point = screen_geometry.center()

        main_window_rect = self.frameGeometry()
        main_window_rect.moveCenter(center_point)

        self.move(main_window_rect.topLeft())


    def send_message_ui(self):
        
        message_label = QLabel('Message:')
        self.message_textbox = QLineEdit()

        signature_label = QLabel('Signature:')

        private_keys = rings.get_all_private_keys_for_user(user_id)
        keys = get_public_keys_ring_for_user(user_id)

        self.signature_dropdown = QComboBox()
        
        for key in private_keys:
            self.signature_dropdown.addItem(key['key_id'])
        self.sender_key = self.signature_dropdown.itemText(0)
        self.signature_dropdown.currentIndexChanged.connect(self.change_sender_key)

        self.sender_password = QLineEdit()
        self.sender_password.setEchoMode(QLineEdit.Password)
        self.signature_checkbox = QCheckBox()

        receiver_key_label = QLabel('Receiver key:')
        self.receiver_key_dropdown = QComboBox()

        algorithm_used_label = QLabel('Algorithm to use:')
        self.algorithm_dropdown = QComboBox()

        for key in keys:
            self.receiver_key_dropdown.addItem(str(key['key_id']))
        self.receiver_key = self.receiver_key_dropdown.itemText(0)
        self.receiver_key_dropdown.currentIndexChanged.connect(self.change_receiver_key)

        self.algorithm_dropdown.addItem('3DES')
        self.algorithm_dropdown.addItem('CAST')
        self.algorithm = self.algorithm_dropdown.itemText(0)
        self.algorithm_dropdown.currentIndexChanged.connect(self.change_algorithm)

        self.receiver_key_checkbox = QCheckBox()

        self.conversion_checkbox = QCheckBox('Conversion')
        self.compression_checkbox = QCheckBox('Compression')

        file_location_label = QLabel('File location:')
        self.file_location_textbox = QLineEdit()
        self.browse_button = QPushButton('Browse')
        self.browse_button.clicked.connect(lambda: self.browse_file_location(self.file_location_textbox))

        self.confirm_button = QPushButton('Confirm')
        self.confirm_button.clicked.connect(self.main_send_message)

        main_layout = QVBoxLayout()

        message_layout = QHBoxLayout()
        message_layout.addWidget(message_label)
        message_layout.addWidget(self.message_textbox)

        signature_layout = QHBoxLayout()
        signature_layout.addWidget(signature_label)
        signature_layout.addWidget(self.signature_dropdown)
        signature_layout.addWidget(self.sender_password)
        signature_layout.addWidget(self.signature_checkbox)

        receiver_key_layout = QHBoxLayout()
        receiver_key_layout.addWidget(receiver_key_label)
        receiver_key_layout.addWidget(self.receiver_key_dropdown)
        receiver_key_layout.addWidget(algorithm_used_label)
        receiver_key_layout.addWidget(self.algorithm_dropdown)
        receiver_key_layout.addWidget(self.receiver_key_checkbox)

        file_location_layout = QHBoxLayout()
        file_location_layout.addWidget(file_location_label)
        self.file_location_textbox.setPlaceholderText("Path to desired file...")
        file_location_layout.addWidget(self.file_location_textbox)
        file_location_layout.addWidget(self.browse_button)

        main_layout.addLayout(message_layout)
        main_layout.addLayout(signature_layout)
        main_layout.addLayout(receiver_key_layout)
        main_layout.addWidget(self.compression_checkbox)
        main_layout.addWidget(self.conversion_checkbox)
        main_layout.addLayout(file_location_layout)
        main_layout.addWidget(self.confirm_button)

        self.tab_send_message.setLayout(main_layout)

    def change_sender_key(self, index):
        self.sender_key = self.signature_dropdown.itemText(index)

    def change_receiver_key(self, index):
        self.receiver_key = self.receiver_key_dropdown.itemText(index)
        
    def change_algorithm(self, index):
        self.algorithm = self.algorithm_dropdown.itemText(index)

    def main_send_message(self):

        message = self.message_textbox.text()
        time_of_sending = str(datetime.datetime.now())
        fileName = self.file_location_textbox.text()

        message = message + "_" + time_of_sending + "_" + fileName

        header = ""
        if self.signature_checkbox.isChecked():
            try:
                private_key = rings.get_private_key_for_key_id(self.sender_key, self.sender_password.text())
                public_key = rings.get_public_key_for_key_id(self.sender_key)
                private_nums = private_key.private_numbers()
                public_nums = public_key.public_numbers()
                message = encryption.signRequest(private_nums.d, public_nums.n, message, self.sender_key)
                header += "S"
            except (ValueError, AttributeError):
                QMessageBox.information(self, "Info", "Wrong password for message signature!")
                return
            
        if self.compression_checkbox.isChecked():
            message = encryption.compress(message)
            header += "C"
        if self.receiver_key_checkbox.isChecked():
            receiver_public_key = rings.get_public_key_for_key_id(self.receiver_key)
            receiver_public_nums = receiver_public_key.public_numbers()
            header += "E"
            if self.algorithm == "3DES":
                header += "T"
            else:
                header += "I"
            message = encryption.encryptMessage(message, receiver_public_nums.e, receiver_public_nums.n, self.receiver_key, header)
            
        if self.conversion_checkbox.isChecked():
            message = encryption.convertToRadix(message)
            header += "R"
        
        message = message + "_" + header

        try:
            with open(fileName, 'w') as file:
                file.write(message)
        except (FileNotFoundError):
            QMessageBox.information(self, "Info", "File with specific name not found!")
            return
        
        QMessageBox.information(self, "Info", "Successfully sent message!")
        return


    def browse_file_location(self, element):
        file_dialog = QFileDialog()
        file_location, _ = file_dialog.getOpenFileName(self, 'Select File')
        if file_location:
            element.setText(file_location)


    def receive_message_ui(self):
        file_location_label = QLabel('File location:')
        self.file_location_textbox_from = QLineEdit()
        self.browse_button_1 = QPushButton('Browse')
        self.browse_button_1.clicked.connect(lambda: self.browse_file_location(self.file_location_textbox_from))

        self.received_message_label = QLabel('')
        font = QFont()
        font.setPointSize(20)
        self.received_message_label.setFont(font)
        self.received_message_label.setAlignment(Qt.AlignCenter)

        save_file_location_label = QLabel('Save file location:')
        self.file_location_textbox_to = QLineEdit()
        self.browse_button_2 = QPushButton('Browse')
        self.browse_button_2.clicked.connect(lambda: self.browse_file_location(self.file_location_textbox_to))

        self.confirm_button2 = QPushButton('Confirm')
        self.confirm_button2.clicked.connect(self.main_receive_message)

        main_layout = QVBoxLayout()

        file_location_layout = QHBoxLayout()
        file_location_layout.addWidget(file_location_label)
        file_location_layout.addWidget(self.file_location_textbox_from)
        
        file_location_layout.addWidget(self.browse_button_1)

        save_file_location_layout = QHBoxLayout()
        save_file_location_layout.addWidget(save_file_location_label)
        save_file_location_layout.addWidget(self.file_location_textbox_to)
        save_file_location_layout.addWidget(self.browse_button_2)

        main_layout.addLayout(file_location_layout)
        main_layout.addWidget(self.received_message_label)
        main_layout.addLayout(save_file_location_layout)
        main_layout.addWidget(self.confirm_button2)

        self.tab_receive_message.setLayout(main_layout)

    def main_receive_message(self):
        message = ""
        try:
            with open(self.file_location_textbox_from.text(), 'r') as file2:
                message = file2.read()
                file2.close()
        except (FileNotFoundError):
            QMessageBox.information(self, "Info", "File for receiving message not found!")
            return

        parts = message.rsplit("_", 1)
        content = parts[0]
        header = parts[1]

        message = self.analyzeHeader(header, content)

        try:
            with open(self.file_location_textbox_to.text(), 'w') as file:
                file.write(message)
                file.close()
        except (FileNotFoundError):
            QMessageBox.information(self, "Info", "File for saving received message not found!")
            return


    def analyzeHeader(self, header, message):

        sender_text = ""

        if "R" in header:
            message = encryption.convertFromRadix(message)
            sender_text += "Poruka je konvertovana iz RADIX-64 formata.\n"
        else:
            sender_text += "Konverzija nije koriscena.\n"
        if "E" in header:
            self.prepare_decryption(message)
            message = encryption.decryptMessage(message, self.receiver_password, header)
            if "I" not in header:
                sender_text += "Poruka je dekriptovana koriscenjem 3DES algoritma.\n"
            else:
                sender_text += "Poruka je dekriptovana koriscenjem CAST5 algoritma.\n"
        else:
            sender_text += "Poruka nije bila sifrovana.\n"
        if "Greska" not in message:
            if "C" in header:
                message = encryption.decompress(message)
                sender_text += "Poruka je dekompresovana.\n\n"
            else:
                sender_text += "Poruka nije bila kompresovana.\n"
            if "S" in header:
                message, sender_data = encryption.verifySignature(message)
                if sender_data != None:
                    sender_text += "SENDER:\n\nUser ID: " + sender_data['user_id'] + "\nUsername: " + sender_data['username'] + "\nTime: " + str(sender_data['timestamp']) + "\nKey ID: " + sender_data['key_id']
            else:
                sender_text += "Posiljalac poruke je odlucio da ostane anoniman.\n"

            if "Greska" in message:
                sender_text = message
            else:
                sender_text = "Uspesno primljena poruka!\n\n" + sender_text
        else:
            sender_text = message

        self.received_message_label.setText(sender_text)
        message = message.split("_")[0]
        
        return message

    def prepare_decryption(self, message):
        self.receiver_password = ""
        self.show_dialog(message)


    def show_dialog(self, message):
        text, ok = QInputDialog.getText(self, 'Unesite lozinku za privatni kljuc', 'Lozinka za dekripciju:', QLineEdit.Password)
        if ok and text:
            self.receiver_password = text


    def key_rings_ui(self):

        self.key_rings_layout = QVBoxLayout()

        self.public_rings_group = QGroupBox("Public Key Ring")
        self.public_rings_layout = QHBoxLayout()
        self.public_ring_table_widget = QTableWidget()

        self.public_rings_layout.addWidget(self.public_ring_table_widget)
        self.public_rings_group.setLayout(self.public_rings_layout)


        self.private_rings_group = QGroupBox("Private Key Ring")
        self.private_rings_layout = QHBoxLayout()
        self.private_ring_table_widget = QTableWidget()

        self.private_rings_layout.addWidget(self.private_ring_table_widget)
        self.private_rings_group.setLayout(self.private_rings_layout)

        self.key_rings_layout.addWidget(self.public_rings_group)
        self.key_rings_layout.addWidget(self.private_rings_group)
        self.tab_key_rings.setLayout(self.key_rings_layout)

    #ucitava sve kljuceve da bi ih prikazao u public ringu
    def populate_table_with_data(self, ring_table_widget, data):

        for row_index, row_data in enumerate(data):
            col_tab = 0

            for col_index, key in enumerate(row_data):
                table_item = QTableWidgetItem(str(row_data[key]))
                ring_table_widget.setItem(row_index, col_tab, QTableWidgetItem(table_item))
                col_tab = col_tab + 1

    def load_key_rings_data(self):

        self.public_ring_table_widget.clearContents()
        self.private_ring_table_widget.clearContents()

        data_public = rings.get_public_key_ring_data()
        data_private = rings.get_private_key_ring_data()

        self.public_ring_table_widget.setRowCount(len(data_public))
        self.populate_table_with_data(self.public_ring_table_widget, data_public)

        self.private_ring_table_widget.setRowCount(len(data_private))
        self.populate_table_with_data(self.private_ring_table_widget, data_private)

    def load_profile_options(self):

        users = rings.get_all_user_ids()
        self.profile_menu.clear()

        for user in users:
            self.add_profile_action(self.profile_menu, user)


    def add_profile_action(self, profile_menu, profile_name):
        profile_action = QAction(profile_name, self)
        profile_action.triggered.connect(lambda: self.select_profile(profile_name))
        profile_menu.addAction(profile_action)

    def select_profile(self, profile_name):
        global user_id
        user_id = profile_name
        self.user_menu.setTitle(user_id)
        self.refresh_data()

    def init_load_key_rings_table(self):

        data_public = rings.get_public_key_ring_data()

        #namestamo odg headere za tabelu...zavise od naziva poda iz ring data
        headers_public = [key[0].upper() + key[1:] for key in data_public[0].keys()]
        self.public_ring_table_widget.setColumnCount(len(headers_public))
        self.public_ring_table_widget.setHorizontalHeaderLabels(headers_public)
        [self.public_ring_table_widget.setColumnWidth(num, 150) for num in range(len(headers_public))]

        data_private = rings.get_private_key_ring_data()

        # namestamo odg headere za tabelu...zavise od naziva pod iz ring data
        headers_private = [key[0].upper() + key[1:] for key in data_private[0].keys()]
        self.private_ring_table_widget.setColumnCount(len(headers_private))
        self.private_ring_table_widget.setHorizontalHeaderLabels(headers_private)
        [self.private_ring_table_widget.setColumnWidth(num, 150) for num in range(len(headers_private))]

        self.load_key_rings_data()

    def key_management_ui(self):

        #sadrzaj taba
        main_layout = QVBoxLayout()
        self.key_generation_group = QGroupBox("Generate new RSA key pair")

        #Layout za groupbox za generisanje kljuceva
        self.key_generation_layout = QGridLayout()

        # sadrzaj key gen groupboxa...
        labels = ["Name:", "Email:", "Key size:", "Private key password:", "Confirm password:"]
        placeholders = ["Enter name", "Enter email", "", "Enter password", "Repeat password"]
        #kreiranje i dodavanje widgeta u key gen layout
        for row, (label, placeholder) in enumerate(zip(labels, placeholders)):
            self.key_generation_layout.addWidget(QLabel(label), row, 0)
            if label == "Key size:":
                combo_box = QComboBox()
                combo_box.addItems(["1024", "2048"])
                self.key_generation_layout.addWidget(combo_box, row, 1)
                self.key_management_inputs[label.lower().replace(":", "").replace(" ", "_")] = combo_box
            else:
                line_edit = QLineEdit()
                line_edit.setPlaceholderText(placeholder)
                if label.startswith("Private") or label.startswith("Confirm"):
                    line_edit.setEchoMode(QLineEdit.Password)
                self.key_generation_layout.addWidget(line_edit, row, 1)
                self.key_management_inputs[label.lower().replace(":", "").replace(" ", "_")] = line_edit

        self.generate_key_button = QPushButton("Generate key")
        self.generate_key_button.clicked.connect(self.gen_key_btn_event)
        self.generate_button_layout = QHBoxLayout()
        self.generate_button_layout.addStretch(2)
        self.generate_button_layout.addWidget(self.generate_key_button)
        self.generate_button_layout.addStretch(2)
        self.generated_key_lable = QLabel("When you start adding keys here will be the KeyID of the last added key...")

        self.key_generation_layout.addLayout(self.generate_button_layout,len(labels), 0, 1, 2)
        self.key_generation_layout.addWidget(self.generated_key_lable, len(labels)+1, 0, 1, 2)
        self.key_generation_layout.setAlignment(Qt.AlignCenter)

        self.key_generation_group.setLayout(self.key_generation_layout)
        main_layout.addWidget(self.key_generation_group)

        self.key_import_export_group = QGroupBox("Import and export keys")
        self.key_import_export_layout = QVBoxLayout()

        #dodavanje novih tabova
        self.import_export_tabs = QTabWidget()
        self.import_full_key_tab = QWidget()
        self.import_public_key_tab = QWidget()
        self.export_public_key_tab = QWidget()
        self.export_whole_key_tab = QWidget()


        #dodavanje novih layouta za tabove
        self.import_full_key_layout = QGridLayout()
        self.import_public_key_layout = QGridLayout()
        self.export_public_key_layout = QGridLayout()
        self.export_whole_key_layout = QGridLayout()

        import_full_labels = ["Name:", "Email:", "Private key password:"]
        import_full_placeholders = ["Enter name", "Enter email", "Enter password"]
        for row, (label, placeholder) in enumerate(zip(import_full_labels, import_full_placeholders)):
            self.import_full_key_layout.addWidget(QLabel(label), row, 0)
            line_edit = QLineEdit()
            line_edit.setPlaceholderText(placeholder)
            if label.startswith("Private"):
                line_edit.setEchoMode(QLineEdit.Password)
            self.import_full_key_layout.addWidget(line_edit, row, 1)
            self.key_management_inputs["import_" + label.lower().replace(":", "").replace(" ", "_")] = line_edit


        self.import_full_key_button = QPushButton("Import whole key")
        self.import_full_key_button.clicked.connect(self.import_full_key)

        import_full_button_layout = QHBoxLayout()
        import_full_button_layout.addStretch(1)
        import_full_button_layout.addWidget(self.import_full_key_button)
        import_full_button_layout.addStretch(1)

        self.import_full_key_layout.addLayout(import_full_button_layout, len(import_full_labels), 0, 4, 3)

        import_public_labels = ["Name:", "Email:"]
        import_public_placeholders = ["Enter name", "Enter email"]
        for row, (label, placeholder) in enumerate(zip(import_public_labels, import_public_placeholders)):
            self.import_public_key_layout.addWidget(QLabel(label), row, 0)
            line_edit = QLineEdit()
            line_edit.setPlaceholderText(placeholder)
            self.import_public_key_layout.addWidget(line_edit, row, 1)
            self.key_management_inputs["import_public_" + label.lower().replace(":", "").replace(" ", "_")] = line_edit

        self.import_public_key_button = QPushButton("Import public key")
        self.import_public_key_button.clicked.connect(self.import_public_key)

        import_public_button_layout = QHBoxLayout()
        import_public_button_layout.addStretch(1)
        import_public_button_layout.addWidget(self.import_public_key_button)
        import_public_button_layout.addStretch(1)

        self.import_public_key_layout.addLayout(import_public_button_layout, len(import_public_labels), 0, 1, 2)


        export_public_labels = ["Key id:", "File location:"]
        for row, label in enumerate(export_public_labels):
            self.export_public_key_layout.addWidget(QLabel(label), row, 0)
            if label == "Key id:":
                combo_box = QComboBox()
                self.export_public_key_layout.addWidget(combo_box, row, 1)
                self.key_management_inputs["export_public_"+label.lower().replace(":", "").replace(" ", "_")] = combo_box
            else:

                # QLineEdit za prikaz putanje fajla
                self.export_public_file_location = QLineEdit()
                self.export_public_file_location.setPlaceholderText("Choose file location")

                self.export_public_key_layout.addWidget(self.export_public_file_location, row, 1)
                self.browse_button = QPushButton("Browse")
                self.browse_button.clicked.connect(self.choose_export_public_location)
                self.export_public_key_layout.addWidget(self.browse_button, row, 2)

                # Neka dugme bude iste visine kao i QLineEdit
                self.browse_button.setFixedHeight(self.export_public_file_location.sizeHint().height())

        self.export_public_key_button = QPushButton("Export public key")
        self.export_public_key_button.clicked.connect(self.export_public_key)

        export_public_button_layout = QHBoxLayout()
        export_public_button_layout.addStretch(1)
        export_public_button_layout.addWidget(self.export_public_key_button)
        export_public_button_layout.addStretch(1)

        self.export_public_key_layout.addLayout(export_public_button_layout, len(import_public_labels), 0, 1, 3)


        export_whole_labels = ["Key id:", "Export public location:", "Export private location:"]
        for row, label in enumerate(export_whole_labels):
            self.export_whole_key_layout.addWidget(QLabel(label), row, 0)
            if label == "Key id:":
                combo_box = QComboBox()
                self.export_whole_key_layout.addWidget(combo_box, row, 1)
                self.key_management_inputs[
                    "export_whole_" + label.lower().replace(":", "").replace(" ", "_")] = combo_box
            else:
                # QLineEdit za prikaz putanje fajla
                file_location = QLineEdit()
                file_location.setPlaceholderText("Choose file location")
                self.export_whole_key_layout.addWidget(file_location, row, 1)

                browse_button2 = QPushButton("Browse")
                if label == "Export public location:":
                    browse_button2.clicked.connect(self.choose_export_whole_pub_location)
                    self.key_management_inputs["export_whole_public_location"] = file_location
                else:
                    browse_button2.clicked.connect(self.choose_export_whole_private_location)
                    self.key_management_inputs["export_whole_private_location"] = file_location

                self.export_whole_key_layout.addWidget(browse_button2, row, 2)

                browse_button2.setFixedHeight(file_location.sizeHint().height())

        self.export_whole_key_button = QPushButton("Export whole key")
        self.export_whole_key_button.clicked.connect(self.export_full_key)

        export_whole_button_layout = QHBoxLayout()
        export_whole_button_layout.addStretch(1)
        export_whole_button_layout.addWidget(self.export_whole_key_button)
        export_whole_button_layout.addStretch(1)

        self.export_whole_key_layout.addLayout(export_whole_button_layout, len(export_whole_labels), 0, 4, 3)

        #setovanje novog layouta za tab
        self.import_full_key_tab.setLayout(self.import_full_key_layout)
        self.import_public_key_tab.setLayout(self.import_public_key_layout)
        self.export_public_key_tab.setLayout(self.export_public_key_layout)
        self.export_whole_key_tab.setLayout(self.export_whole_key_layout)

        #povezavnje novih tabova za glavni layout
        self.import_export_tabs.addTab(self.import_public_key_tab, "Import public key")
        self.import_export_tabs.addTab(self.export_public_key_tab, "Export public key")
        self.import_export_tabs.addTab(self.import_full_key_tab, "Import whole key")
        self.import_export_tabs.addTab(self.export_whole_key_tab, "Export whole key")


        #povezivanje glavnog taba za layout i setovanje tog layouta za key management gui
        self.key_import_export_layout.addWidget(self.import_export_tabs)
        self.key_import_export_group.setLayout(self.key_import_export_layout)


        main_layout.addWidget(self.key_import_export_group)

        self.key_deletion_group = QGroupBox("Delete keys")
        self.key_deletion_layout = QVBoxLayout()
        self.keys_list = QListWidget()
        self.keys_list.itemSelectionChanged.connect(self.on_item_selection_changed)
        self.additional_data_label = QLabel("")


        self.delete_key_button = QPushButton("Delete chosen key")
        self.delete_key_button.clicked.connect(self.delete_key)
        self.delete_key_button.setMaximumWidth(150)

        self.delete_key_button_layout = QHBoxLayout()
        self.delete_key_button_layout.addStretch(1)  # dodaje prazam prostor ispred i iza dugmeta
        self.delete_key_button_layout.addWidget(self.delete_key_button)  # dodaje dugme izmedju
        self.delete_key_button_layout.addStretch(1)


        self.key_deletion_layout.addWidget(self.keys_list)
        self.key_deletion_layout.addLayout(self.delete_key_button_layout)
        self.key_deletion_layout.addWidget(self.additional_data_label)
        self.key_deletion_group.setLayout(self.key_deletion_layout)


        main_layout.addWidget(self.key_deletion_group)

        self.tab_key_management.setLayout(main_layout)

    def choose_export_public_location(self):

        file_path, _ = QFileDialog.getOpenFileName(self, "Select public pem location", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.export_public_file_location.setText(file_path)

    def choose_export_whole_pub_location(self):

        file_path, _ = QFileDialog.getOpenFileName(self, "Select public pem location", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.key_management_inputs["export_whole_public_location"].setText(file_path)

    def choose_export_whole_private_location(self):

        file_path, _ = QFileDialog.getOpenFileName(self, "Select private pem location", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.key_management_inputs["export_whole_private_location"].setText(file_path)

    def show_password_dialog(self):

        password, ok = QInputDialog.getText(self, "Enter Password", "Enter password for the private key:",QLineEdit.Password)

        return password, ok

    def populate_export_combo_box(self):
        
        self.key_management_inputs['export_public_key_id'].clear()
        self.key_management_inputs['export_public_key_id'].addItems([key_data[0] for key_data in self.gui_key_list])
        self.key_management_inputs['export_whole_key_id'].clear()
        self.key_management_inputs['export_whole_key_id'].addItems([key_data[0] for key_data in self.gui_key_list if key_data[2] != rings.KeyType.IMPORTED_PUBLIC ])

    def populate_send_message_tab(self):
        self.signature_dropdown.clear()
        self.signature_dropdown.addItems(key_data['key_id'] for key_data in rings.get_all_private_keys_for_user(user_id))
        self.sender_key = self.signature_dropdown.itemText(0)
        self.receiver_key_dropdown.clear()
        self.receiver_key_dropdown.addItems(key_data['key_id'] for key_data in rings.get_public_keys_ring_for_user(user_id))     
        self.receiver_key = self.receiver_key_dropdown.itemText(0)

    def gen_key_btn_event(self):

        name = self.key_management_inputs['name'].text()
        email = self.key_management_inputs['email'].text()
        key_size = int(self.key_management_inputs['key_size'].currentText())
        password = self.key_management_inputs['private_key_password'].text()
        password2 = self.key_management_inputs['confirm_password'].text()
        if password != password2:
            QMessageBox.information(self, "Error", "Passwords do not match!")
            return

        if name == "" or email == "" or password == "" or password2 == "":
            QMessageBox.information(self, "Info", "Please ensure all fields are filled.")
            return


        self.new_key_id = rings.generate_new_key(name=name, email=email, key_size=key_size, password=password)
        self.generated_key_lable.setText("Last added key has KeyID = {} and was created by {}".format(self.new_key_id, name))
        add_data = "User: " + name + ", " + "Email: " + email + ", " + "Datetime: " + str(datetime.datetime.now()) + ", generated )"
        self.gui_key_list.append([self.new_key_id, add_data, rings.KeyType.GENERATED])
        self.refresh_data()
        QMessageBox.information(self, "Info", "Key generated successfully.")

    def refresh_data(self):

        self.load_keys_for_delete_list()
        self.load_key_rings_data()
        self.populate_send_message_tab()
        self.populate_export_combo_box()
        self.load_profile_options()
        self.clear_inputs()
        self.load_profile_options()



    def import_full_key(self):

        password = self.key_management_inputs['import_private_key_password'].text()
        name = self.key_management_inputs['import_name'].text()
        email = self.key_management_inputs['import_email'].text()

        if password == "" or name == "" or email == "":
            QMessageBox.information(self, "Info", "Please ensure all fields are filled.")
            return


        # biramo private pem
        private_key_file, _ = QFileDialog.getOpenFileName(self, "Choose private key pem", "",
                                                          "PEM Files (*.pem);;All Files (*)")
        if not private_key_file:
            QMessageBox.information(self, "Info", "Private key file not chosen.")
            return

        public_key_file, _ = QFileDialog.getOpenFileName(self, "Choose public key pem", "",
                                                         "PEM Files (*.pem);;All Files (*)")
        if not public_key_file:
            QMessageBox.information(self, "Info", "Public key file not chosen.")
            return

        imported_key_id = rings.import_whole_key(public_key_file, private_key_file, name, email, password)
        #Greska
        if imported_key_id == -1:
            QMessageBox.information(self, "Info", "Incorrect password.")
            return

        add_data = "User: " + name + ", " + "Email: " + email + ", " + "Datetime: " + str(datetime.datetime.now())+ ", imported whole key )"
        self.gui_key_list.append([imported_key_id, add_data, rings.KeyType.IMPORTED_WHOLE])
        self.refresh_data()
        QMessageBox.information(self, "Info", "Whole key imported.")


    def import_public_key(self):

        name = self.key_management_inputs['import_public_name'].text()
        email = self.key_management_inputs['import_public_email'].text()

        if name == "" or email == "":
            QMessageBox.information(self, "Info", "Please ensure all fields are filled.")
            return

        public_key_file, _ = QFileDialog.getOpenFileName(self, "Choose public key pem", "",
                                                   "PEM Files (*.pem);;All Files (*)")

        if not public_key_file:
            QMessageBox.information(self, "Info", "File not chosen.")
            return

        imported_key_id = rings.import_public_key(public_key_file, name, email)
        add_data = ("User: " + name + ", " + "Email: " + email + ", " + "Datetime: " +
                    str(datetime.datetime.now()) + ", imported public key)")
        self.gui_key_list.append([imported_key_id, add_data, rings.KeyType.IMPORTED_PUBLIC])
        self.refresh_data()

        QMessageBox.information(self, "Info", "Public key imported.")


    def export_full_key(self):

        public_loc = self.key_management_inputs["export_whole_public_location"].text()
        private_loc = self.key_management_inputs["export_whole_private_location"].text()

        if public_loc == "" or private_loc == "":
            QMessageBox.information(self, "Info", "Please ensure all fields are filled.")
            return

        key_id = self.key_management_inputs['export_whole_key_id'].currentText()
        password, ok = self.show_password_dialog()
        if not ok:
            QMessageBox.information(self, "Info", "Password invalid.")
            return


        status = rings.export_whole_key(key_id, password, public_loc, private_loc)

        if status == -1:
            QMessageBox.information(self, "Info", "Password incorrect.")
            return

        QMessageBox.information(self, "Info", "Whole key is successfully exported.")

        self.key_management_inputs["export_whole_public_location"].clear()
        self.key_management_inputs["export_whole_private_location"].clear()

    def export_public_key(self):

        key_id = self.key_management_inputs['export_public_key_id'].currentText()

        public_loc = self.export_public_file_location.text()
        if public_loc == "":
            QMessageBox.information(self, "Info", "Please ensure all fields are filled.")
            return

        status = rings.export_public_key(key_id, public_loc)
        if status == -1:
            QMessageBox.information(self, "Info", "Public key not exported.")
            return
        QMessageBox.information(self, "Info", "Public key is successfully exported.")

        self.export_public_file_location.clear()


    def delete_key(self):

        selected_key = self.keys_list.currentItem()

        if selected_key is None:
            QMessageBox.information(self, "Info", "Please select the key.")
            return

        key_id = selected_key.text()

        password = ""
        for key_data in self.gui_key_list:
            if key_data[0] == key_id:
                if key_data[2] != rings.KeyType.IMPORTED_PUBLIC:
                    password, ok = self.show_password_dialog()
                    if not ok:
                        # QMessageBox.information(self, "Info", "Password not.")
                        return
                break

        if rings.delete_rsa_key(key_id, password):
            self.keys_list.takeItem(self.keys_list.row(selected_key))
            for elem in self.gui_key_list:
                if elem[0] == selected_key.text():
                    self.gui_key_list.remove(elem)
            QMessageBox.information(self, "Info", "Key is successfully deleted.")
            self.refresh_data()
        else:
            QMessageBox.information(self, "Info", "Incorrect password.")

    def load_keys_for_delete_list(self):

        self.keys_list.clear()
        keys = self.gui_key_list

        for text, additional_data, type in keys:
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, additional_data)
            #lepa boja siva je i 200, 200, 200
            if type == rings.KeyType.GENERATED:
                #item.setBackground(QColor(200, 200, 200))
                item.setBackground(QColor(70, 130, 180))
            else:
                #item.setBackground(QColor(180, 180, 180))
                item.setBackground(QColor(255, 165, 180))

            self.keys_list.addItem(item)
    def on_item_selection_changed(self):
        selected_items = self.keys_list.selectedItems()
        if selected_items:
            selected_item = selected_items[0]
            additional_data = selected_item.data(Qt.UserRole)
            self.additional_data_label.setText(f"Additional Data: {additional_data}")
        else:
            self.additional_data_label.setText("Additional Data:")

    def clear_inputs(self):
        for input_widget in self.key_management_inputs.values():
            if isinstance(input_widget, QLineEdit):
                input_widget.clear()
            elif isinstance(input_widget, QComboBox):
                input_widget.setCurrentIndex(0)

    def init_data(self):
        #proizvoljni podaci
        names = ["Marko", "Jovan", "Stefan", "Tea", "Marija", "Jelena"]
        emails = ["marko@gmail.com", "jovan@gmail.com", "stefan@gmail.com", "tea@gmail.com", "marija@gmail.com"]
        key_sizes = [1024, 1024, 2048, 1024, 2048]
        password_postfix = "123"
        #dodajemo nekoliko kljuceva u sistem...
        for row, (name, email, key_size) in enumerate(zip(names, emails, key_sizes)):
            key_id = rings.generate_new_key(name, email, key_size, name+password_postfix)
            #public_key = rings.get_public_key_for_key_id(key_id)
            #print(f"e:{public_key.public_numbers().e}")
            #print(f"n:{public_key.public_numbers().n}")
            add_data = "( User: " + name + ", " + "Email: " + email + ", " + "Datetime: " + str(datetime.datetime.now())+ ", generated )"
            self.gui_key_list.append([key_id, add_data, rings.KeyType.GENERATED])
            self.new_key_id = key_id

        #kreiramo po jedan pem da mozemo da testiramo import kljuceva
        pub_key, pub_pem, priv_key, priv_pem = rings_utils.generate_rsa_key_pair(2048, "test1")
        pub_key1, pub_pem1, priv_key1, priv_pem1 = rings_utils.generate_rsa_key_pair(2048, "test2")
        rings_utils.write_pem_to_file(pub_pem, "test1_export_pub_key.pem")
        rings_utils.write_pem_to_file(priv_pem, "test1_export_priv_key.pem")
        rings_utils.write_pem_to_file(pub_pem1, "test2_export_pub_key.pem")
        rings_utils.write_pem_to_file(priv_pem1, "test2_export_priv_key.pem")


if __name__ == '__main__':

    app = QApplication([])
    main_window = PGPApp()
    main_window.show()
    sys.exit(app.exec_())
