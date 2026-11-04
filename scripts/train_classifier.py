import numpy as np
from xgboost import XGBClassifier

print("Testing XGBoost and Python environment...")

# [complexity, ast_depth, loc, maintainability_idx]
X_dummy = np.array([[15, 8, 120, 45], [3, 2, 25, 88], [28, 14, 310, 30]])
y_dummy = np.array([1, 0, 1])  # 1 = Vulnerable, 0 = Safe

model = XGBClassifier(n_estimators=50, max_depth=4)
model.fit(X_dummy, y_dummy)

preds = model.predict(X_dummy)
print(f"XGBoost Model Trained Successfully! Predictions: {preds}")
