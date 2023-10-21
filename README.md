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
###### Request Types
- `ListLeaderboards`
  - Additional client request fields:
    - None
  - Resource server response `data`:
    - A `list` of leaderboards, each a tuple of the following:
      - id of the leaderboard
      - name of the leaderboard
      - permission of the requesting user (see `enums.py` for values)
- `ShowOneLeaderboard`
  - Additional client request fields:
    - `leaderboard_id`: the id of the leaderboard requested
  - Resource server response `data`:
    - A `dict` containing the following:
      - `id`: the id of the leaderboard
      - `name`: the name of the leaderboard
      - `entries`: a `list` of tuples sorted by score in the proper orientation with the following:
        - the id of the entry
        - the id of the submitting user
        - the identity (name) of the submitting user
        - the submitter's score
        - the submission date as an int
        - the submission's verified status
- `CreateLeaderboard`
  - Additional client request fields:
    - `leaderboard_name`: the name for the new leaderboard
    - `leaderboard_permission`: the default permission for the new leaderboard
    - `leaderboard_ascending`: `True` to sort scores ascending, `False` to sort descending.
  - Resource server response `data`:
    - The new leaderboard's id
- `AddEntry`
  - Additional client request fields:
    - `leaderboard_id`: id of the leaderboard
    - `score`: the score
    - `comment`: a comment / description
  - Resource server response `data`:
    - the new entry's id
- `ListUsers`
  - Additional client request fields:
    - None
  - Resource server response `data`:
    - a `list` of tuples each with:
      - id of the user
      - identity of the user (username, effectively)
- `ListUnverified`
  - Additional client request fields:
    - `leaderboard_id`: id of the leaderboard
  - Resource server response `data`:
    - a `list` of unverified entries, each a tuple with the following:
      - the entry id
      - the submitting user's id
      - the submitting user's identity
      - entry score
      - date entry submitted
- `GetEntry`
  - Additional client request fields:
    - `entry_id`: the id of the requested entry
  - Resource server response `data`:
    - a `dict` with the following fields:
      - `entry`, a tuple of the following items:
        - the id of the entry
        - the id of the submitter
        - the identity of the submitter
        - score of the entry
        - submission date
        - verified state
        - verifying user's id
        - verifying user's identity
      - `comments`: a `list` of tuples, each with the following items:
        - posting user's identity
        - posting date
        - content of the comment
      - `files`: a `list` of tuples, each with the following items:
        - id of the file
        - filename
        - date of submission
- `ViewUser`
  - Additional client request fields:
    - `'user_id`: the id of the requested user
  - Resource server response `data`:
    - a `dict` with the following entries:
      - `user_data`: a tuple of the following items
        - identity of the user
        - registration date
      - `entries`: a `list` of tuples visible to the requesting user, each with the following items:
        - id of the entry
        - id of the leaderboard associated
        - score on the entry
        - verified boolean
        - submission date
- `ViewPermissions`
  - Additional client request fields:
    - `user_id`: the id of the user whose permissions will be viewed
  - Resource server response `data`:
    - a `list` of tuples each with:
      - the id of a leaderboard
      - the permission of the user for this leaderboard
- `ModifyEntryVerification`
  - Additional client request fields:
    - `entry_id`: the id of the entry to change
    - `verified`: the state to set (boolean)
  - Resource server response `data`:
    - `None`, use `success` alone to determine outcome.
- `AddComment`
  - Additional client request fields:
    - `entry_id`: the id of the entry to add comment to
    - `content`: the text content of the comment
  - Resource server response `data`:
    - `None`, use `success` alone to determine outcome.
- `RemoveLeaderboard`
  - Removes all comments, entries, and files associated with leaderboard as well as the leaderboard itself
  - Additional client request fields:
    - `leaderboard_id`: the id of the leaderboard to remove
  - Resource server response `data`:
    - `None`, use `success` alone to determine outcome.
- `RemoveEntry`
  - Removes all comments, files and the entry from leaderboard.
  - Additional client request fields:
    - `entry_id`: the id of the entry to remove
  - Resource server response `data`
    - `None`, use `success` alone to determine outcome
- `SetPermission`
  - Sets a user's permission for a leaderboard to a certain permission level. Can update a current permission or set a new permission.
  - Additional client request fields:
    - `user_id`: the id of the user whose permission is to be updated
    - `leaderboard_id`: the leaderboard for the permission
    - `permission`: the new permission for the user
  - Resource server response `data`
    - `None`, use `success` alone to determine outcome
- `RemoveUser`
  - Removes a user and associated data from the database.
  - Additional client request fields:
    - `user_id`: the id of the user to be removed
  - Resource server response `data`
    - `None`, use `success` alone to determine outcome
- Further TODOS in enums.py

### Clientside Commands
#### Basic Commands
- READ: list leaderboards
  - shows all leaderboard names on this server
- READ: open leaderboard [leaderboard name]
  - sets local state variable 'leaderboard' to the specified leaderboard name  
- ADMIN: create leaderboard [leaderboard name]
  - adds a leaderboard with the specified name
- READ: list users
  - outputs a list of all users with ID and identity
  - Additional client request fields:
    - None
  - Resource server response:
    - A `list` of users, each a tuple of `(id, identity)`
- READ: open user [user ID]
  - sets local state variable 'user' to the specified ID
- READ: open self
  - sets local state variable 'user' to the logged in user's ID
#### Commands Associated With a Leaderboard
- READ: list entries
  - shows all verified entries (ID, place, player name, score, date/time) on the leaderboard
- MOD: list unverified
  - shows all unverified entries (ID, place, player name, score, date/time) on the leaderboard
- WRITE: submit entry
  - then prompted to enter
    - score
    - description
- READ: open entry [entry ID]
  - sets local state variable 'entry' to the specified entry ID
- ADMIN: score order [ascending/descending]
  - set the ordering of scores to be ascending or descending
- ADMIN: remove leaderboard
  - deletes leaderboard from the database (after asking to confirm)
#### Commands Associated With an Entry
- READ/MOD: view entry
  - Access Denied if entry is unverified and user is not moderator
  - show the ID, place on the leaderboard, player name, score, date/time of submission, date/time of verification and who verified it (if none, declare it to be so), list of proof files, and number of comments for the current entry
- WRITE: add proof [filename]
  - must be original author of the submission
  - upload specified file as a proof file to this entry
- READ/MOD: download proof [filename] into [local filename]
  - Access Denied if entry is unverified and user is not moderator
  - download the proof file into the local filename specified
- READ/MOD: view comments
  - Access Denied if entry is unverified and user is not moderator
  - show all comments, printing poster's name, text content of the message, and a date/time. chronologically ordered.
- WRITE/MOD: post comment [message]
  - Must be owner of submission or moderator
  - add a comment containing your message
- MOD: verify entry
  - mark the entry as verified
- MOD: unverify entry
  - mark the entry as unverified
- WRITE/MOD: remove entry
  - Must be owner of submission or moderator
  - take the entry out of the database
#### Commands Associated With a User
- READ: view user [user_id]
  - Access Denied if requester has No Access
  - Gives an error if a user with the id doesn't exist
  - Shows the name and registration date of the user
  - Lists all entries from a user that the requester has access to
- MOD: view permissions [user_id]
  - List all permissions given to this user, as leaderboard:access pairs
- MOD: set user [user_id] permission for [leaderboard_id] to [permission]
  - sets the user's access level for the given leaderboard
- READ: open submission [entry ID]
  - sets local state variable 'entry' to the given ID
  - note: this replicates behavior for open entry, bad thing?
- ADMIN: remove user
  - deletes user from database (with confirmation)
  - optionally deletes all content associated with that user
    - this sounds really hard :)
    - not sure what should be deleted and what should be anonymized
