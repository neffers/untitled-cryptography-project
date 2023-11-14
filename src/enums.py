from enum import IntEnum, auto


# An enum for Request types to the Resource Server
# Should hopefully simplify adding request types as well as determining if all cases are handled
class ResourceRequestType(IntEnum):
    PublicKey = auto()
    Authenticate = auto()
    NonceReply = auto()
    ListLeaderboards = auto()
    ShowOneLeaderboard = auto()
    CreateLeaderboard = auto()
    AddEntry = auto()
    ListUsers = auto()
    ListUnverified = auto()
    ListAccessGroups = auto()
    GetEntry = auto()
    ViewUser = auto()
    ViewPermissions = auto()
    ModifyEntryVerification = auto()
    RemoveLeaderboard = auto()
    AddComment = auto()
    RemoveEntry = auto()
    SetPermission = auto()
    RemoveUser = auto()
    ChangeScoreOrder = auto()
    AddProof = auto()
    DownloadProof = auto()
    RemoveProof = auto()
    GetSelfID = auto()


class ServerErrCode(IntEnum):
    AuthenticationFailure = auto()
    InsufficientPermission = auto()
    DoesNotExist = auto()
    MalformedRequest = auto()


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
