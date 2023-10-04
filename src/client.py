"""
set your identity and authentication server once, to be stored on disk unless modified
pick from a list of previously connected resource servers or add a resource server
once you pick a server, pick a request to make and send the request and identity to the AS
when you receive the permission packet from AS, send the identity, request type, and permissions
    to the RS you selected earlier
when you receive the response from the RS, display results
you can then make another request using that same AS response (which violates complete mediation)
    so maybe you have to ask the AS for another response actually?
or you can quit the client application
"""
