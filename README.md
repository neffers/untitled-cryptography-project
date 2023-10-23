[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/bfJ6ciUj)  
Please see the [Phase 2 description](desc/phase_2.pdf) for details.

### High Level Overview
#### General
- Using Python 3.8 or later
- Transferring data using JSON over TCP
- Storing data serverside using SQLite
- Server handles packets with a concurrent callback
- Databases write to disk on every modification
#### Resource Server
- Expects packets containing an identity token and a request, along with details to execute the request
- The token is used to determine the permissions of the request maker, using a database of users stored locally
- The request is fulfilled if the permissions allow it, otherwise an "Access Denied" packet is sent back
- Most requests are fulfilled by reading or writing to the leaderboard database on disk.
#### Authentication Server
- Expects packets with an identity and any required credentials (right now, nothing)
- If the credentials check out, responds with a token to represent that identity (right now, just the identity itself)
#### Client Application
- Facilitates requests and outputs responses to/from auth. and res. servers
- Stores on disk
  - Identity and credentials (no credentials for now)
  - Previously specified resource server IP's, ports, and custom names
  - A single authentication server IP and port
- Enables user to modify the information listed above, or make a request to a chosen resource server.
- Transparently requests token from auth. server and uses the token to make further requests to the resource server while that token is valid (for now, forever)
- Upon receiving the response back from the resource server, displays the response and prompts for another request or allows the user to quit

[Permissions](./doc/permissions.pdf)

[Request Types](./doc/request_types.pdf)

[Clientside Commands](./doc/clientside_commands.pdf)
