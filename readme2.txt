permissions:

access:    resource:                    condition:
----------------------------------------------------------------------
default permission level '0' - "non-user"
----------------------------------------------------------------------
read       leaderboard
read       score_evidence
read       score_evidence_comments
write      username_registration
----------------------------------------------------------------------
permission level '1' - "registered user"
----------------------------------------------------------------------
read       leaderboard
both       score_submissions            submission is from their user
read       submissions_management       submission is from their user
both       submissions_comments         submission is from their user
----------------------------------------------------------------------
permission level '2' - "moderator"
----------------------------------------------------------------------
read       leaderboard
both       score_submissions
both       submissions_management
both       submissions_comments
----------------------------------------------------------------------
permission level '3' - "administrator"/"owner"
----------------------------------------------------------------------
both       leaderboard
both       score_submissions
both       submissions_management
both       moderators_management



resource table:

resource:                     functionality:                             availability:
----------------------------------------------------------------------------------------------------------
leaderboard                   display of leaderboard                     perm 0+
score_evidence                display of evidence for scores             perm 0+
score_evidence_comments       display of comments on evidence            perm 0+
username_registration         register non-user (perm 0 -> 1)            perm 0
score_submissions             process of submitting a score              user who submitted, perm 2+
submissions_management        process of accepting/rejecting score       user who submitted, perm 2+
submissions_comments          commenting on score judgement              user who submitted, perm 2+
moderators_management         controlling who is moderator               perm 3