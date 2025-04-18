from fastapi import FastAPI
from packet_sniffer import capture_packets
import pickle
import numpy as np
# from logistic import LogisticRegression  # Needed before unpickling
from random_forest import RandomForest, DecisionTree, DecisionTreeNode

app = FastAPI()

# ✅ Load the model globally
with open("models/best_model1.pkl", "rb") as f:
    model = pickle.load(f)
    print("Model loaded:", type(model))
    print("Predict:", model.predict(np.zeros((1, 14))))
    print("Probabilities:", model.predict_prob(np.zeros((1, 14))))



def classify_packet(features):
    print("classifying...")

    try:
        # Define the exact order of features expected by the model
        feature_order = [
            "same_srv_rate", "dst_host_srv_count", "dst_host_same_srv_rate", "logged_in",
            "flag", "dst_host_srv_serror_rate", "dst_host_serror_rate",
            "serror_rate", "srv_serror_rate", "count", "dst_host_count",
            "difficulty_score", "service", "rerror_rate"
        ]

        # Map service (string) to numerical value
        service_map = {
            "22": 1, "23": 2, "80": 3, "443": 4,
            "unknown": 0  # Add more if needed
        }

        # Clean and encode service
        service_val = str(features.get("service", "unknown"))
        features["service"] = service_map.get(service_val, 0)

        # Ensure all required features are present and numerical
        feature_vector = [float(features.get(feat, 0)) for feat in feature_order]

        feature_vector = np.array([feature_vector])
        print("Feature vector used for prediction:", feature_vector)
        pred = model.predict(feature_vector)

        print(pred[0])

        return "Anomalous" if pred[0] == 1 else "Normal"

    except Exception as e:
        print("[ERROR] During classification:", e)
        return "Error"


@app.get("/")
def home():
    return {"message": "NIDS Backend Running"}

@app.get("/capture/{count}")
def capture(count: int = 10):
    try:
        packets = capture_packets(count)
        if not packets:
            return {"error": "No packets captured."}

        results = [{"features": pkt, "classification": classify_packet(pkt)} for pkt in packets]
        return {"packets": results}

    except Exception as e:
        print("[ERROR] During capture:", str(e))
        return {"error": "Packet capture failed", "details": str(e)}

# Optional local dev run
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
