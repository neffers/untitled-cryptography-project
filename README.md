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

### Permissions
#### Authentication Server
- Anyone can log in to an account if they provide the proper credentials (nothing)
- Anyone can add an account to the authentication server if they have a unique identity and provide credentials to use
  - for now it is assumed that your account is already created and valid for any identity
#### Resource Server
- Anyone can view
  - A list of users and the user's ID, name, creation date, list of verified entries, and permissions for each leaderboard
  - A list of leaderboards for which all users are granted Read Access
- For a given leaderboard, a user has some permission level.
  - No Access
    - No resources can be accessed besides those which are publicly readable, all other requests responded to with Access Denied  
  - Read Access
    - Verified entries can be viewed, including ID, place, player name, score, date/time of submission, date/time of verification and who verified it, a list of proof files, the content of proof files, the number of comments and the comments themselves.
  - Write Access (includes Read Access)
    - Submissions can be created, including score, description, and proof files
    - **All** entries from this user can be viewed and comments can be added, or the entry can be removed
  - Moderator (includes Write Access)
    - Unverified entries from any user can be viewed
    - Comments can be added to any unverified entry
    - An unverified entry can be verified
    - An entry can be removed
    - Permissions for any user with below moderator access can be modified for this leaderboard
- Admin includes Moderator permissions **for all leaderboards** plus
  - Create/delete leaderboards
  - set leaderboard score order
  - Delete users
  - Modify permissions for any user for any leaderboard
- The first user to connect to a resource server is given admin permissions
##### Making Requests
- All client requests to the resource server should include the following fields:
  - `identity` the identity used to log in to the auth server
  - `token` the token received back from the auth server
  - `type` the type of request. Should use a ResourceRequestType enum from `enums.py`
  - additional fields as required by the request type
- All Resource server responses will include the following fields
  - `success` a boolean indicating if the requested operation was successful or not
  - `data` a blob of data formatted depending on the request
    - Upon failure, this will simply be a string indicating a reason for the failure.
- Additionally, the resource server will serve all dates as unix epoch ints

[Request Types](./doc/request_types.md)

[Clientside Commands](./doc/clientside_commands.md)
