import gevent
import gevent.event
import gevent.monkey
gevent.monkey.patch_socket()
import gevent.queue
import storestub


def _shared_hack():
     # hack to get around circular import
     import shared
     global app
     app = shared.app


def make_redis():
    _shared_hack()
    host = app.config["REDIS_HOST"]
    port = app.config.get("REDIS_PORT") or 6379
    redis = __import__("redis")
    return redis.Redis(host=host, port=port, db=0, decode_responses=True)


class Keystore:
    def __init__(self):
        _shared_hack()
        self._backend = app.config.get("STORE_PROVIDER") or "INTERNAL"
        if self._backend == "REDIS":
           self._client = make_redis()
        else:
            self._client = storestub.KeystoreClient()
            self._client.connect()
    def get(self, key):
        return self._client.get(key)
    def exists(self, key):
        if self._backend == "REDIS":
            return self._client.exists(key) != 0
        else:
            return self._client.get(key) != None
    def set(self, key, value):
        self._client.set(key, value)
    def delete(self, key):
        self._client.delete(key)
    def clear(self):
        if self._backend == "REDIS":
            self._client.flushdb()
        else:
            self._client.clear()


class Pubsub:
    def __init__(self):
        _shared_hack()
        self._backend = app.config.get("STORE_PROVIDER") or "INTERNAL"
        if self._backend == "REDIS":
            self._channels = {}
            self._pump_running = False
            self._subscriptions = set()
            self._connect_redis_pubsub()
        else:
            self._client = storestub.PubsubClient()
            self._client.connect()
    def subscribe(self, channel):
        if self._backend == "REDIS":
            self._subscriptions.add(channel)
            self._pubsub_client.subscribe(channel)
        else:
            self._client.subscribe(channel)
    def unsubscribe(self, channel):
        if self._backend == "REDIS":
            self._subscriptions.discard(channel)
            self._pubsub_client.unsubscribe(channel)
        else:
            self._client.unsubscribe(channel)
    def publish(self, channel, message):
        if self._backend == "REDIS":
            self._redis_client.publish(channel, message)
        else:
            self._client.publish(channel, message)
    def get_message(self, channel):
        if self._backend == "REDIS":
            self._ensure_pump()
            self._ensure_channel(channel)
            return self._channels[channel].get()
        else:
            return self._client.get_message(channel)
    def _ensure_pump(self):
        if self._pump_running:
            return
        self._pump_running = True
        gevent.spawn(self._redis_pump)
    def _redis_pump(self):
        while True:
            try:
                for response in self._pubsub_client.listen():
                    channel = response["channel"]
                    message = response["data"]
                    self._ensure_channel(channel)
                    self._channels[channel].put(message)
            except Exception as exc:
                app.logger.warning("Redis pubsub connection dropped; reconnecting: %s", exc)
                gevent.sleep(1)
                self._reconnect_redis_pubsub()
    def _connect_redis_pubsub(self):
        self._redis_client = make_redis()
        self._pubsub_client = self._redis_client.pubsub(ignore_subscribe_messages=True)
    def _reconnect_redis_pubsub(self):
        while True:
            try:
                try:
                    self._pubsub_client.close()
                except Exception:
                    pass
                self._connect_redis_pubsub()
                if self._subscriptions:
                    self._pubsub_client.subscribe(*list(self._subscriptions))
                return
            except Exception as exc:
                app.logger.warning("Redis pubsub reconnect failed; retrying: %s", exc)
                gevent.sleep(2)
    def _ensure_channel(self, channel):
        if channel not in self._channels:
            self._channels[channel] = gevent.queue.Queue()
