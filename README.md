[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/bfJ6ciUj)
Please see the [Phase 2 description](desc/phase_2.pdf) for details.

using latest stable python3 venv  
each program transfers data using json over TCP. ports input at startup or read from file  
packets received have to be handled concurrently with one another  
modifications can technically be written to disk only when a proper shutdown occurs but that sounds like it can easily mess up if we crash  

resource server  
json packet contains an identity from the authentication server which has been proved  
the identity has to be looked up in a table of permissions  
if the person can perform the request they are making according to the table, respond with the answer to the request, otherwise respond with an access denied packet.  

authentication server  
json packets received should contain an identity and a request type.  
the AS responds with a token to represent the identity  

client  
set your identity and authentication server once, to be stored on disk unless modified  
pick from a list of previously connected resource servers or add a resource server  
once you pick a server, pick a request to make and send the request and identity to the AS  
when you receive the permission packet from AS, send the identity, request type, and permissions to the RS you selected earlier  
when you receive the response from the RS, display results  
you can then make another request using that same AS response (which violates complete mediation) so maybe you have to ask the AS for another response actually?  
or you can quit the client application  

types of requests and what data they act on:  
//TODO  
permissions:  
//TODO  
