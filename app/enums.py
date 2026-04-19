from enum import Enum


class UserRole(str, Enum):

    ADMIN = "admin"
    STAFF = "staff"
    CLIENT = "client"
