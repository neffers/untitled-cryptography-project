from enum import IntEnum
from enum import auto


# An enum for Request types to the Resource Server
# Should hopefully simplify adding request types as well as determining if all cases are handled
class ResourceRequestType(IntEnum):
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
    GetIdFromIdentity = auto()
    ListAccess = auto()


class Permissions(IntEnum):
    # we want these to have a specific hierarchy
    NoAccess = 0
    Read = 1
    Write = 2
    Moderate = 3


class UserClass(IntEnum):
    User = Permissions.NoAccess
    Administrator = Permissions.Moderate
