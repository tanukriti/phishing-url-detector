from flask import Flask, render_template, request
import pickle
import numpy as np

app = Flask(__name__)

# Load the trained model
model = pickle.load(open("phishing_model.pkl", "rb"))

@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None

    if request.method == "POST":
        # Collect 30 feature values from form
        features = [int(x) for x in request.form.values()]
        features = np.array(features).reshape(1, -1)

        result = model.predict(features)[0]
        prediction = "⚠️ Phishing Website" if result == 1 else "✅ Legitimate Website"

    return render_template("index.html", prediction=prediction)

if __name__ == "__main__":
    app.run(debug=True)
