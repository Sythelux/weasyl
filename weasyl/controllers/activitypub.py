import asyncio
import json

from pyramid.response import Response

from libweasyl import key_management
from libweasyl.exceptions import WeasylError
from libweasyl.key_management import KeyManager, KeyRotation
from weasyl import define, config
from weasyl.config import config_obj

key_manager = None
initialized = False
initializing = False


async def init_app():
    """Initialize the application and its dependencies."""
    global key_manager, delivery, discovery, signature_verifier, initialized

    try:
        # Initialize components with proper configuration
        key_manager = KeyManager(
            domain=define.get_domain(),
            keys_path=config_obj.get('activitypub', 'keys_path'),
            rotation_config=KeyRotation(
                rotation_interval=30,  # 30 days
                key_overlap=2,  # 2 days overlap
                key_size=2048  # RSA key size
            )
        )
        await key_manager.initialize()
        initialized = True
    except Exception as e:
        define.append_to_log(__name__, level="error", msg=f"Failed to initialize application: {e}")
        raise WeasylError(e)


async def actvitypub_profile(userprofile):
    """Return actor information."""
    try:
        url = define.absolutify_url("users")
        username = userprofile["username"]

        # Get active key for public key info
        active_key = await key_manager.get_active_key()

        response = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "type": "Person",
            "id": f"{url}/{username}",
            "preferredUsername": username,
            # "inbox": f"{url}/{username}/inbox", TODO: later
            "outbox": f"{url}/{username}/outbox",
            "followers": f"{url}/{username}/followers",
            "publicKey": {
                "id": active_key.key_id,
                "owner": f"{url}/{username}",
                "publicKeyPem": await key_manager.get_public_key_pem(username)
            }
        }

        return Response(
            text=json.dumps(response),
            content_type='application/activity+json'
        )

    except Exception as e:
        define.append_to_log(__name__, level="error", msg=f"Error in actor handler: {e}")
        raise WeasylError("internal server error", str(e))
        # raise web.HTTPInternalServerError(reason=str(e))


def key_handler(request):
    pass


if not initialized and not initializing:
    initializing = True
    loop = asyncio.get_event_loop()
    res = loop.run_until_complete(init_app())
    initializing = False
