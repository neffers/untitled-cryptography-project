from enum import IntEnum, auto


# An enum for Request types to the Resource Server
# Should hopefully simplify adding request types as well as determining if all cases are handled
class ResourceRequestType(IntEnum):
    # These happen in order for the handshake
    PublicKey = 0
    Authenticate = 1
    NonceReply = 2

    # These are the actual server functionality
    AddComment = auto()
    AddEntry = auto()
    AddPermission = auto()
    AddProof = auto()
    ChangeScoreOrder = auto()
    CreateLeaderboard = auto()
    DownloadProof = auto()
    GetEntry = auto()
    GetKeys = auto()
    GetSelfID = auto()
    ListAccessGroups = auto()
    ListLeaderboards = auto()
    ListUnverified = auto()
    ListUsers = auto()
    ModifyEntryVerification = auto()
    RemoveEntry = auto()
    RemoveLeaderboard = auto()
    RemovePermission = auto()
    RemoveProof = auto()
    RemoveUser = auto()
    ShowOneLeaderboard = auto()
    ViewPermissions = auto()
    ViewUser = auto()


class ServerErrCode(IntEnum):
    AuthenticationFailure = auto()
    DoesNotExist = auto()
    InsufficientPermission = auto()
    MalformedRequest = auto()
    SessionExpired = auto()


class Permissions(IntEnum):
    # we want these to have a specific hierarchy
    NoAccess = 0
    Read = 1
    Write = 2
    Moderate = 3


class UserClass(IntEnum):
    User = Permissions.NoAccess
    Administrator = Permissions.Moderate


class AuthRequestType(IntEnum):
    PublicKey = auto()
    Token = auto()
