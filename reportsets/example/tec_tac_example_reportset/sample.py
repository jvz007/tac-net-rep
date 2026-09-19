def map_sample_data(raw: dict) -> dict:
    """Map raw extension data into a tiny report-facing representation."""
    return {
        "device": raw["device_name"],
        "status": "up" if raw["reachable"] else "down",
        "latency_ms": raw["latency_ms"],
    }
