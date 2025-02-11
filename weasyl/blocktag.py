from libweasyl import ratings
from libweasyl.cache import region

from weasyl import define as d
from weasyl import profile
from weasyl import searchtag

# For blocked tags, `rating` refers to the lowest rating for which that tag is
# blocked; for example, (X, Y, 10) would block tag Y for all ratings, whereas
# (X, Y, 30) would block tag Y for only adult ratings.


def check(userid, submitid=None, charid=None, journalid=None):
    """
    Returns True if the submission, character, or journal contains a search tag
    that the user has blocked, else False.
    """
    if not userid:
        return False

    if submitid:
        map_table = "searchmapsubmit"
        content_table = "submission"
        id_field = "submitid"
        target = submitid
    elif charid:
        map_table = "searchmapchar"
        content_table = "character"
        id_field = "charid"
        target = charid
    else:
        map_table = "searchmapjournal"
        content_table = "journal"
        id_field = "journalid"
        target = journalid

    query = """
        SELECT EXISTS (
            SELECT 0 FROM {map_table} searchmap
                INNER JOIN {content_table} content ON searchmap.targetid = content.{id_field}
            WHERE searchmap.targetid = %(id)s
                AND content.userid != %(user)s
                AND searchmap.tagid IN (
                    SELECT blocktag.tagid FROM blocktag
                    WHERE userid = %(user)s AND blocktag.rating <= content.rating)) AS block
    """.format(map_table=map_table, content_table=content_table, id_field=id_field)

    return d.engine.execute(query, id=target, user=userid).first().block


def check_list(rating, tags, blocked_tags):
    return any(rating >= b['rating'] and b['tagid'] in tags for b in blocked_tags)


def select(userid):
    return [{
        "title": i[0],
        "rating": i[1],
    } for i in d.execute("SELECT st.title, bt.rating FROM searchtag st "
                         " INNER JOIN blocktag bt ON st.tagid = bt.tagid"
                         " WHERE bt.userid = %i"
                         " ORDER BY st.title", [userid])]


@region.cache_on_arguments()
@d.record_timing
def select_ids(userid):
    return [
        dict(row)
        for row in d.engine.execute(
            'SELECT tagid, rating FROM blocktag WHERE userid = %(user)s',
            user=userid)
    ]


def insert(userid: int, tags: str, rating: int):
    if rating not in ratings.CODE_MAP:
        rating = ratings.GENERAL.code

    profile.check_user_rating_allowed(userid, rating)

    parsed_tags = searchtag.parse_tags(tags)

    d.engine.execute('''
        INSERT INTO blocktag (userid, tagid, rating)
        SELECT %(user)s, tag, %(rating)s
        FROM UNNEST (%(tag)s::integer[]) AS tag
        ON CONFLICT (userid, tagid) DO UPDATE
        SET rating = EXCLUDED.rating
    ''', user=userid, tag=searchtag.get_or_create_many(parsed_tags), rating=rating)

    select_ids.invalidate(userid)


def remove_list(userid: int, tags: list[str]):
    if not tags:
        return

    d.engine.execute('''
        DELETE FROM blocktag
        WHERE userid = %(userid)s
        AND tagid IN (
            SELECT tagid
            FROM searchtag
            WHERE title = ANY (%(tags)s)
        )
    ''', userid=userid, tags=tags)

    select_ids.invalidate(userid)
