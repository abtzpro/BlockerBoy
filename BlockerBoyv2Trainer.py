from sklearn.ensemble import IsolationForest
from sklearn import datasets
import joblib

# Load KDDCup99 dataset
kddcup99 = datasets.fetch_kddcup99(subset='http')

# Convert data and target to the correct format
X = kddcup99['data'].astype(float)

# Process the target data
Y = kddcup99['target']
Y = (Y == b'normal.').astype(int)

# Use only normal data for training (anomaly detection is about detecting deviations from 'normal')
X_train = X[Y == 1]

# Train the model
model = IsolationForest(contamination=0.01)
model.fit(X_train)

# Save the model
joblib.dump(model, 'isolation_forest_model.pkl')
