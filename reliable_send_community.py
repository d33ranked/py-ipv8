class AckCache(RandomNumberCacheWithName):
    name = "ack-cache"

    def __init__(self, request_cache: RequestCache, value:0) -> None:
        super().__init__(request_cache, self.name)
        self.value = value

    def on_timeout(self):
        print("response missed")
    
    @property
    def timeout_delay(self) -> float:
        return 3.0