from enum import IntEnum
from enum import auto


# An enum for Request types to the Resource Server
# Should hopefully simplify adding request types as well as determining if all cases are handled
class ResourceRequestType(IntEnum):
    ShowLeaderboards = auto()
    ShowOneLeaderboard = auto()
