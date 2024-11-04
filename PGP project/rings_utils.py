import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


#----------------------------------data---------------------------------------
private_keys_ring = {}
public_keys_ring = {}



#----------------------------------functions---------------------------------------
def hash_and_derive_key(password):

    hashed_password = hashlib.sha1(password.encode()).digest()
    key = hashed_password[-16:]
    return key, hashed_password


def get_hex_val_of_private_key(private_key):

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    hex_val = private_key_der.hex()
    return hex_val


#racunamo hes tako sto hesiramo pem, a zatim uzmemo nizih 8 bajtova i pretvaramo u hex broj
def get_key_id_for_public_key(key):

    key_der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo

    )

    hashed_pem = hashlib.sha1(key_der).digest()
    key_id = hashed_pem[-8:]
    key_id_hex = key_id.hex()
    return key_id_hex


def generate_rsa_key_pair(key_size, password):


    password_bytes = password.encode()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )


    public_key = private_key.public_key()


    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key, public_pem, private_key, private_pem


def read_pem_from_file(filename):

    with open(filename, "r") as file:
        key_pem_str = file.read()

    return key_pem_str


def write_pem_to_file(key_pem, filename):

    key_pem_str = key_pem.decode('utf-8')
    with open(filename, "w") as file:
        file.write(key_pem_str)

