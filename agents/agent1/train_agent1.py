"""Train Agent 1 with duplicate-group holdout validation."""
import argparse, json, os, time
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.utils.class_weight import compute_sample_weight

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--train",required=True); p.add_argument("--out",default="artifacts")
    a=p.parse_args(); os.makedirs(a.out,exist_ok=True)
    df=pd.read_csv(a.train)
    if "label" not in df: raise ValueError("Expected target column named 'label'")
    y=df.label.astype(str).str.strip()
    X=df.drop(columns=["label","record_id"],errors="ignore")
    X=X.apply(pd.to_numeric,errors="coerce").replace([np.inf,-np.inf],np.nan)
    X=X.dropna(axis=1,how="all"); X=X.loc[:,X.nunique(dropna=True)>1]
    groups=pd.util.hash_pandas_object(X,index=False).to_numpy()
    tr,te=next(GroupShuffleSplit(n_splits=1,test_size=.2,random_state=42).split(X,y,groups))
    imp=SimpleImputer(strategy="median"); xt=imp.fit_transform(X.iloc[tr]); xv=imp.transform(X.iloc[te])
    model=HistGradientBoostingClassifier(max_iter=120,learning_rate=.12,max_leaf_nodes=31,l2_regularization=1.,random_state=42)
    start=time.time(); yt,yv=y.iloc[tr],y.iloc[te]
    model.fit(xt,yt,sample_weight=compute_sample_weight("balanced",yt)); pred=model.predict(xv)
    dg=pd.DataFrame({"group":groups,"label":y}).groupby("group").label
    report={"rows":len(df),"features":X.shape[1],"train_rows":len(tr),"holdout_rows":len(te),
      "split":"80/20 GroupShuffleSplit grouped by exact feature-row hash",
      "duplicate_feature_rows":int(X.duplicated().sum()),
      "conflicting_duplicate_feature_groups":int((dg.nunique()>1).sum()),
      "training_seconds":round(time.time()-start,2),"accuracy":float(accuracy_score(yv,pred)),
      "macro_f1":float(f1_score(yv,pred,average="macro")),
      "classification_report":classification_report(yv,pred,output_dict=True,zero_division=0),
      "confusion_matrix":confusion_matrix(yv,pred,labels=model.classes_).tolist(),
      "class_order":model.classes_.tolist(),"class_counts":{str(k):int(v) for k,v in y.value_counts().items()},
      "note":"Internal grouped holdout only. Evaluate on the organiser's untouched official evaluation set before claiming benchmark performance."}
    joblib.dump({"imputer":imp,"model":model,"feature_names":X.columns.tolist(),"classes":model.classes_.tolist(),"version":"1.1.0"},os.path.join(a.out,"threat_detection_model.joblib"),compress=3)
    with open(os.path.join(a.out,"training_report.json"),"w",encoding="utf-8") as f: json.dump(report,f,indent=2)
    print(json.dumps({k:report[k] for k in ("rows","features","train_rows","holdout_rows","accuracy","macro_f1")},indent=2))
if __name__=="__main__": main()
