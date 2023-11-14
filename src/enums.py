from enum import IntEnum, auto


# An enum for Request types to the Resource Server
# Should hopefully simplify adding request types as well as determining if all cases are handled
class ResourceRequestType(IntEnum):
    AddComment = auto()
    AddEntry = auto()
    AddProof = auto()
    Authenticate = auto()
    ChangeScoreOrder = auto()
    CreateLeaderboard = auto()
    DownloadProof = auto()
    GetEntry = auto()
    GetSelfID = auto()
    ListAccessGroups = auto()
    ListLeaderboards = auto()
    ListUnverified = auto()
    ListUsers = auto()
    ModifyEntryVerification = auto()
    NonceReply = auto()
    PublicKey = auto()
    RemoveEntry = auto()
    RemoveLeaderboard = auto()
    RemoveProof = auto()
    RemoveUser = auto()
    SetPermission = auto()
    ShowOneLeaderboard = auto()
    ViewPermissions = auto()
    ViewUser = auto()


class ServerErrCode(IntEnum):
    AuthenticationFailure = auto()
    DoesNotExist = auto()
    InsufficientPermission = auto()
    MalformedRequest = auto()
    Timeout = auto()


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
