import bcrypt


def encrypt_password(password: str) -> bytes:
    bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(bytes, salt)

    return hashed_password


def check_password(password: bytes, raw_password: str):
    bytes_given_password = raw_password.encode('utf-8')

    return bcrypt.checkpw(bytes_given_password, password)