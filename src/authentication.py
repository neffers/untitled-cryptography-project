"""
json packets received should contain an identity and a request type.
the AS responds with a token to represent the identity
"""

import socket
import json

def response_token(token):
    return {"type": token, "token": token}
