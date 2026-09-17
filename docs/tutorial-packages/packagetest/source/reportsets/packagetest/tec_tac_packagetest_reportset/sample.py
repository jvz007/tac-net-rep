def map_device(payload):
    return {"device":payload["device"],"status":payload["status"],"latency_ms":payload["latency_ms"],"reportset":"packagetest"}
