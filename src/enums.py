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
    GetEntry = auto()
    ViewUser = auto()
    ViewPermissions = auto()
    ModifyEntryVerification = auto()
    RemoveLeaderboard = auto()
    AddComment = auto()
    RemoveEntry = auto()
    SetPermission = auto()
    # TODOS
    # Admin: Score Order
    # Entry: Add Proof
    # Entry: Download Proof
    # User: Remove User
