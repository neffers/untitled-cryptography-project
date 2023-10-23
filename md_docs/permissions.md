# Permissions
This is the system that is used for determining user permission and access levels for the servers.
## Authentication Server
A server that handles the login process, and provides a user with a token that specifies their identity for the Resource Server
- Anyone can log in to an account if they provide the proper credentials (identity)
- Anyone can add an account through the authentication server if they have a unique identity and provide credentials to use
  - for now it is assumed that your account is already created and valid for any identity
## Resource Server
The server that houses the leaderboards. Different users can access different parts of the server and are allowed to modify different things.
### Public Features
  - A list of users and the user's ID, name, creation date, list of verified entries, and permissions for each leaderboard
  - A list of leaderboards for which all users are granted Read Access
### Permission Levels
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
### Administrator Privileges
- Admin includes Moderator permissions **for all leaderboards** plus
  - Create/delete leaderboards
  - set leaderboard score order
  - Delete users
  - Modify permissions for any user for any leaderboard
- The first user to connect to a resource server is given admin permissions