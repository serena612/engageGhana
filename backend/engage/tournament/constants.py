from common.mixins import LabelChoices


class BracketFormat(LabelChoices):
    SINGLE_ELIMINATION = 'single_elimination', 'Single Elimination'
    DOUBLE_ELIMINATION = 'double_elimination', 'Double Elimination'
    FREE_FOR_ALL = 'free_for_all', 'Free For All'
    ROUND_ROBIN = 'round_robin', 'Round Robin'


class TournamentStatus(LabelChoices):
    ONLINE = 'online', 'Online'
    OFFLINE = 'offline', 'offline'


class ParticipantStatus(LabelChoices):
    PENDING = 'pending', 'Pending'
    ACCEPTED = 'accepted', 'Accepted'
    DECLINED = 'declined', 'Declined'


class Platform(LabelChoices):
    PC = 'pc', 'PC',
    SWITCH = 'switch', 'Nintendo Switch'
    PLAYSTATION = 'playstation', 'Playstation'
    XBOX = 'xbox', 'Xbox'
    ANDROID = 'android', 'Android'
    IOS = 'ios', 'iOS'


class TournamentState(LabelChoices):
    UPCOMING = 'upcoming', 'Upcoming'
    ONGOING = 'ongoing', 'Ongoing'
    PAST = 'past', 'Past'


class MatchStatus(LabelChoices):
    UPCOMING = 'upcoming', 'Upcoming'
    ONGOING = 'ongoing', 'Ongoing'
    FINISHED = 'finished', 'Finished'
    CANCELED = 'canceled', 'Canceled'


class TournamentPrizeType(LabelChoices):
    CASH = 'cash', 'Cash'
    # TICKETS = 'tickets', 'Tickets'
    DATA = 'data', 'Data'
    OTHERS = 'others', 'Others'
    AIRTIME = 'airtime', 'Airtime'



class RoundNumber(LabelChoices):
    FIRST = 1, '1st Round'
    SECOND = 2, '2nd Round'
    THIRD = 3, '3rd Round'
    FOURTH = 4, '4th Round'
    FIFTH = 5, '5th Round'
    SIXTH = 6, '6th Round'
    SEVENTH = 7, '7th Round'
    EIGHTH = 8, '8th Round'
    NINTH = 9, '9th Round'
    TENTH = 10, '10th Round'
    ELEVENTH = 11, '11th Round'
    TWELFTH = 12, '12th Round'
    THIRTEENTH = 13, '13th Round'
    FOURTEENTH = 14, '14th Round'
    FIFTEENTH = 15, '15th Round'
    SIXTEENTH = 16, '16th Round'
    SEVENTEENTH = 17, '17th Round'
    EIGHTEENTH = 18, '18th Round'
    NINETEENTH = 19, '19th Round'
    TWENTIETH = 20, '20th Round'
