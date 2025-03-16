import random

def classify_packet(features):
    """Simulate ML classification by randomly returning 'Normal' or 'Anomalous'."""
    return random.choice(["Normal", "Anomalous"])
