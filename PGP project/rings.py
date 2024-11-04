import datetime
import traceback

import rings_utils
from rings_utils import *
from enum import Enum

#odredjuje tip kljuca

class KeyType(Enum):
    GENERATED = 0
    IMPORTED_PUBLIC = 1
    IMPORTED_WHOLE = 2

#u ringu cuvamo vrednosti pemova!
#od pema moze da se dodje do objekta rsaprivatekey...
def generate_new_key(name, email, key_size, password):

    timestamp = datetime.datetime.now()
    public_key, public_pem, private_key, enc_private_pem = generate_rsa_key_pair(key_size, password)
    key_id = get_key_id_for_public_key(public_key)
    user_id = email

    public_keys_ring[key_id] = {
            'timestamp': timestamp,
            'key_id': key_id,
            'user_id': user_id,
            'username': name,
            'public_key': public_pem,
    }

    private_keys_ring[key_id] = {
            'timestamp': timestamp,
            'key_id': key_id,
            'user_id': email,
            'public_key': public_pem,
            'encrypted_private_key': enc_private_pem
    }
    return key_id


def delete_rsa_key(key_id, password):

    password_bytes = ""
    if len(password) != 0:
        password_bytes = password.encode()


    try:
        if key_id in private_keys_ring:
            encrypted_private_pem = private_keys_ring[key_id]['encrypted_private_key']

            #ako ne baci gresku znaci dobra sifra
            private_key = serialization.load_pem_private_key(
                encrypted_private_pem,
                password=password_bytes,
                backend=default_backend()
            )
            private_keys_ring.pop(key_id)

        public_keys_ring.pop(key_id)

        return True

    except (ValueError, TypeError):
        print("Nije dobra lozinka!")
        traceback.print_exc()
        return False


def import_public_key(filename_public, name, email):

    public_pem, public_key = import_public_key_from_file(filename_public)
    key_id = rings_utils.get_key_id_for_public_key(public_key)
    add_elem_to_public_ring(key_id, name, email, public_pem)

    return key_id


def import_whole_key(filename_public, filename_private, name, email, password):

    public_pem, public_key = import_public_key_from_file(filename_public)
    private_pem, private_key = import_private_key_from_file(filename_private, password)

    if private_pem == None or private_key == None:
        #Greska nije dobar kljuc
        return -1

    key_id = rings_utils.get_key_id_for_public_key(public_key)
    add_elem_to_public_ring(key_id, name, email, public_pem)
    add_elem_to_private_ring(key_id, email, public_pem, private_pem)

    return key_id

def export_public_key(key_id, filename):

    public_pem = get_public_pem_for_key_id(key_id)
    if public_pem is None:
        return -1
    write_pem_to_file(public_pem, filename)
    return 0


def export_private_key(private_pem, filename):

    write_pem_to_file(private_pem, filename)


def import_public_key_from_file(filename):

    public_key_pem_str = read_pem_from_file(filename)
    public_key = serialization.load_pem_public_key(
        public_key_pem_str.encode(),
        backend=default_backend()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem, public_key


def import_private_key_from_file(filename, password):
    enc_private_key_pem = read_pem_from_file(filename)
    try:
        private_key = serialization.load_pem_private_key(
            enc_private_key_pem.encode(),
            password=password.encode(),
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        return private_pem, private_key

    except(ValueError, TypeError):
        #print("Nije dobra lozinka prilikom importa celog kljuca!")
        traceback.print_exc()
        return None, None


def export_whole_key(key_id, password, filename_public, filename_private):

    public_pem = get_public_pem_for_key_id(key_id)
    private_pem = get_private_pem_for_key_id(key_id, password)

    if private_pem is None:
        return -1

    write_pem_to_file(public_pem, filename_public)
    write_pem_to_file(private_pem, filename_private)
    return 0


def add_elem_to_public_ring(key_id, name, email, public_pem):

    timestamp = datetime.datetime.now()
    public_keys_ring[key_id] = {
        'timestamp': timestamp,
        'key_id': key_id,
        'user_id': email,
        'username': name,
        'public_key': public_pem,
    }


def add_elem_to_private_ring(key_id, email, public_pem, private_pem):

    timestamp = datetime.datetime.now()
    private_keys_ring[key_id] = {
        'timestamp': timestamp,
        'key_id': key_id,
        'user_id': email,
        'public_key': public_pem,
        'encrypted_private_key': private_pem
    }


def get_public_key_for_key_id(key_id):

    public_key_pem = public_keys_ring[key_id]['public_key']
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    return public_key


def get_private_key_for_key_id(key_id, password):

    try:
        if key_id in private_keys_ring:
            enc_private_pem = private_keys_ring[key_id]['encrypted_private_key']

            private_key = serialization.load_pem_private_key(
                enc_private_pem,
                password=password.encode(),
                backend=default_backend()
            )
            return private_key
        else:
            return None

    except (ValueError, TypeError):
        #print("Nije doba lozinka!")
        traceback.print_exc()
        return None



def get_all_private_keys_for_user(user_id):

    private_keys_for_user = [
        private_keys_ring[key_id] for key_id in private_keys_ring.keys()
        if private_keys_ring[key_id]['user_id'] == user_id
    ]
    return private_keys_for_user


def get_public_keys_ring_for_user(user_id):

    public_keys_ring_for_user =[
        public_keys_ring[key_id] for key_id in public_keys_ring.keys()
        if public_keys_ring[key_id]['user_id'] != user_id
    ]

    return public_keys_ring_for_user


def get_public_pem_for_key_id(key_id):

    if key_id in public_keys_ring:
        public_key_pem = public_keys_ring[key_id]['public_key']
        return public_key_pem
    else:
        return None

def get_private_pem_for_key_id(key_id, password):

    if key_id in private_keys_ring:
        if get_private_key_for_key_id(key_id, password) is None:
            return None
        private_pem = private_keys_ring[key_id]['encrypted_private_key']
        return private_pem
    else:
        return None


def get_public_key_ring_data():

    public_keys_ring_data = [
        public_keys_ring[key_id] for key_id in public_keys_ring.keys()
    ]
    return public_keys_ring_data


def get_private_key_ring_data():

    private_keys_ring_data = [
        private_keys_ring[key_id] for key_id in private_keys_ring.keys()
    ]
    return private_keys_ring_data


def get_all_user_ids():

    user_ids = set([public_keys_ring[key_id]['user_id'] for key_id in public_keys_ring])

    return list(user_ids)






