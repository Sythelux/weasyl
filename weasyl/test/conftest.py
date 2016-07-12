# pytest configuration for weasyl db test fixture.
# The filename conftest.py is magical, do not change.

import pyramid.testing
import pytest
import web

from weasyl import config
config._in_test = True  # noqa

from libweasyl.configuration import configure_libweasyl
from libweasyl.models.tables import metadata
from weasyl import cache, define, emailer, macro, media
cache.region.configure('dogpile.cache.memory')
define.metric = lambda *a, **kw: None


configure_libweasyl(
    dbsession=define.sessionmaker,
    not_found_exception=web.notfound,
    base_file_path='testing',
    staff_config_dict={},
    media_link_formatter_callback=media.format_media_link,
)


@pytest.fixture(scope='session', autouse=True)
def setupdb(request):
    define.engine.execute('DROP SCHEMA public CASCADE')
    define.engine.execute('CREATE SCHEMA public')
    define.engine.execute('CREATE EXTENSION HSTORE')
    define.meta.create_all(define.engine)


@pytest.fixture(autouse=True)
def setup_request_environment(request):
    pyramid_request = pyramid.testing.DummyRequest()
    pyramid_request.set_property(define.pg_connection_request_property, name='pg_connection', reify=True)
    pyramid_request.set_property(define.userid_request_property, name='userid', reify=True)
    pyramid_request.log_exc = define.log_exc_request_method
    pyramid_request.web_input = define.web_input_request_method
    pyramid_request.environ['HTTP_X_FORWARDED_FOR'] = '127.0.0.1'
    pyramid_request.client_addr = '127.0.0.1'
    pyramid.testing.setUp(request=pyramid_request)

    def tear_down():
        pyramid_request.pg_connection.close()
        pyramid.testing.tearDown()

    # TODO: Delete this web.py logic when everything is updated.
    web.ctx.env = {'HTTP_X_FORWARDED_FOR': '127.0.0.1'}
    web.ctx.ip = '127.0.0.1'
    request.addfinalizer(tear_down)


@pytest.fixture(autouse=True)
def lower_bcrypt_rounds(monkeypatch):
    monkeypatch.setattr(macro, 'MACRO_BCRYPT_ROUNDS', 4)


@pytest.fixture(autouse=True)
def drop_email(monkeypatch):
    def drop_append(mailto, mailfrom, subject, content, displayto=None):
        pass

    monkeypatch.setattr(emailer, 'append', drop_append)


@pytest.fixture
def db(request):
    db = define.connect()

    def tear_down():
        """ Clears all rows from the test database. """
        db.flush()
        for table in metadata.tables.values():
            db.execute(table.delete())

    request.addfinalizer(tear_down)
    return db
