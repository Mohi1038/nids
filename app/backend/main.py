from fastapi import FastAPI
from packet_sniffer import capture_packets
from model_loader import classify_packet

app = FastAPI()

@app.get("/")
def home():
    return {"message": "NIDS Backend Running"}

@app.get("/capture/{count}")
def capture(count: int = 10):
    """Capture multiple packets, extract features, and classify them."""
    packets = capture_packets(count)  # Capture 'count' packets

    if not packets:
        return {"error": "No packets captured."}

    results = [{"features": pkt, "classification": classify_packet(pkt)} for pkt in packets]

    return {"packets": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
