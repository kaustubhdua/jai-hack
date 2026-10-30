"""Load a trained Agent 1 artifact and score flow records from CSV."""
import argparse, joblib, numpy as np, pandas as pd
def main():
    p=argparse.ArgumentParser(); p.add_argument("--model",required=True); p.add_argument("--input",required=True); p.add_argument("--output",default="predictions.csv"); a=p.parse_args()
    artifact=joblib.load(a.model); frame=pd.read_csv(a.input)
    features=frame.reindex(columns=artifact["feature_names"])
    features=features.apply(pd.to_numeric,errors="coerce").replace([np.inf,-np.inf],np.nan)
    matrix=artifact["imputer"].transform(features); result=frame.copy()
    result["predicted_label"]=artifact["model"].predict(matrix)
    if hasattr(artifact["model"],"predict_proba"): result["confidence"]=artifact["model"].predict_proba(matrix).max(axis=1)
    result.to_csv(a.output,index=False); print(f"Wrote {len(result)} predictions to {a.output}")
if __name__=="__main__": main()
