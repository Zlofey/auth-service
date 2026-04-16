import bcrypt

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """
    Hash password using bcrypt.

    Note: bcrypt has a 72-byte limit, so we truncate longer passwords.
    This is safe because we still verify against the truncated version.
    """
    # Truncate password to 72 characters (bcrypt limitation)
    password = password[:72]
    # Generate salt and hash
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password against hash.

    Note: We truncate to 72 characters to match the hashing behavior.
    """
    # Truncate password to 72 characters (bcrypt limitation)
    plain_password = plain_password[:72]
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )
