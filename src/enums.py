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
    # TODOS
    # Admin: Score Order
    # Admin: Remove Leaderboard
    # Entry: Add Proof
    # Entry: Download Proof
    # Entry: Add comment
    # Entry: Verify Entry
    # Entry: Unverify Entry
    # Entry: Remove Entry
    # User: View User (get visible entries)
    # User: View Permission
    # User: Set Permission
    # User: Remove User
