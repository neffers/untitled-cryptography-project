"""
json packet contains an identity including all of the permissions of the identity as well as a request
    for some action or access
if the json packet says that the person has permission to do that action, do the action and respond
    along the TCP socket with another json packet containing the response
"""

