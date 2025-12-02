from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"] , deprecated= "auto")

def verify_password(plain_password, hashed_password):
    """
        Verify the incoming password with stored hash password
    """
    return pwd_context.verify(plain_password,hashed_password)

def hash_password(plain_password):
    """
    Hashes a plain-text password using bcrypt.
    """
    return pwd_context.hash(plain_password)
