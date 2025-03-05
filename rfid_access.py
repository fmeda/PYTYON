# rfid_access.py

import rfid

class RFIDAccessControl:
    def __init__(self, rfid_reader):
        self.reader = rfid.Reader(rfid_reader)

    def authenticate_user(self, rfid_tag):
        # Verificar se o RFID corresponde a um usuário autorizado
        if self.reader.read_tag() == rfid_tag:
            return True
        return False
