"""Neon Postgres persistence and first-party authentication for CyberSentinel."""
from __future__ import annotations
import base64, hashlib, hmac, json, os, re, secrets, time
from urllib.parse import parse_qs
from typing import Any
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = "cybersentinel"
EVENT_TABLES = {"agent2_inference_events","flow_analysis_events","replay_decisions","replay_policies","replay_correlation_groups","analysis_runs"}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
TOKEN_TTL_SECONDS = 43200
class AuthError(Exception): pass

def database_configured(): return bool(os.environ.get("DATABASE_URL") and os.environ.get("AUTH_SECRET"))
def connect():
    url=os.environ.get("DATABASE_URL","").strip()
    if not url: raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(url,connect_timeout=8,row_factory=dict_row,options="-c search_path=cybersentinel,public")
def _b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
def _unb64(value): return base64.urlsafe_b64decode(value+"="*(-len(value)%4))
def _hash_password(password,salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,600000)
    return "pbkdf2_sha256$600000$"+_b64(salt)+"$"+_b64(digest)
def _password_matches(password,encoded):
    try:
        algorithm,rounds,salt,expected=encoded.split("$",3)
        if algorithm!="pbkdf2_sha256" or int(rounds)<300000:return False
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),_unb64(salt),int(rounds))
        return hmac.compare_digest(actual,_unb64(expected))
    except (ValueError,TypeError):return False
def _sign_token(user):
    secret=os.environ.get("AUTH_SECRET","")
    if len(secret)<32:raise RuntimeError("AUTH_SECRET must contain at least 32 characters")
    header=_b64(json.dumps({"alg":"HS256","typ":"JWT"},separators=(",",":")).encode())
    now=int(time.time())
    payload=_b64(json.dumps({"sub":str(user["id"]),"email":user["email"],"iat":now,"exp":now+TOKEN_TTL_SECONDS,"iss":"cybersentinel"},separators=(",",":")).encode())
    msg=(header+"."+payload).encode("ascii")
    return header+"."+payload+"."+_b64(hmac.new(secret.encode(),msg,hashlib.sha256).digest())
def verify_token(token):
    try:
        header,payload,signature=token.split(".")
        secret=os.environ.get("AUTH_SECRET","")
        msg=(header+"."+payload).encode("ascii")
        if len(secret)<32 or not hmac.compare_digest(hmac.new(secret.encode(),msg,hashlib.sha256).digest(),_unb64(signature)):raise AuthError("Invalid session token.")
        claims=json.loads(_unb64(payload))
        if claims.get("iss")!="cybersentinel" or int(claims.get("exp",0))<=int(time.time()):raise AuthError("Your session expired. Please sign in again.")
        with connect() as conn:user=conn.execute("SELECT id,email,created_at FROM users WHERE id=%s AND is_active=true",(str(claims["sub"]),)).fetchone()
        if not user:raise AuthError("Account is unavailable.")
        return {"id":str(user["id"]),"email":user["email"],"created_at":user["created_at"].isoformat()}
    except AuthError:raise
    except Exception as exc:raise AuthError("Invalid or expired session.") from exc
def register_user(email,password):
    email=email.strip().lower()
    if len(email)>254 or not EMAIL_RE.fullmatch(email):raise ValueError("Enter a valid email address.")
    if len(password)<8 or len(password)>128:raise ValueError("Password must be between 8 and 128 characters.")
    try:
        with connect() as conn:row=conn.execute("INSERT INTO users(email,password_hash) VALUES(%s,%s) RETURNING id,email,created_at",(email,_hash_password(password))).fetchone()
    except psycopg.errors.UniqueViolation as exc:raise ValueError("An account with this email already exists.") from exc
    user={"id":str(row["id"]),"email":row["email"],"created_at":row["created_at"].isoformat()}
    return {"user":user,"access_token":_sign_token(user),"token_type":"bearer","expires_in":TOKEN_TTL_SECONDS}
def login_user(email,password):
    email=email.strip().lower()
    email_hash=hashlib.sha256(email.encode('utf-8')).hexdigest()
    with connect() as conn:
        conn.execute("DELETE FROM auth_rate_limits WHERE attempted_at < now() - interval '1 day'")
        attempts=conn.execute("SELECT count(*) AS attempts FROM auth_rate_limits WHERE email_hash=%s AND attempted_at > now() - interval '15 minutes'",(email_hash,)).fetchone()['attempts']
        if attempts >= 10:
            too_many=True
            row=None
        else:
            too_many=False
            conn.execute('INSERT INTO auth_rate_limits(email_hash) VALUES(%s)',(email_hash,))
            row=conn.execute('SELECT id,email,password_hash,created_at FROM users WHERE email=%s AND is_active=true',(email,)).fetchone()
    # Exit the transaction before raising so failed attempts are committed.
    if too_many: raise AuthError('Too many sign-in attempts. Wait 15 minutes and try again.')
    if not row or not _password_matches(password,row['password_hash']): raise AuthError('Email or password is incorrect.')
    with connect() as conn:
        conn.execute('DELETE FROM auth_rate_limits WHERE email_hash=%s',(email_hash,))
    user={'id':str(row['id']),'email':row['email'],'created_at':row['created_at'].isoformat()}
    return {'user':user,'access_token':_sign_token(user),'token_type':'bearer','expires_in':TOKEN_TTL_SECONDS}


def current_user_from_request(request):
    auth=request.headers.get("authorization","")
    if not auth.lower().startswith("bearer "):raise AuthError("Sign in to continue.")
    return verify_token(auth.split(" ",1)[1].strip())
def insert_rows(table,rows,user_id):
    if not rows:return {"stored":True,"backend":"neon_postgres","rows":0}
    if table=="replay_runs":
        with connect() as conn:
            for r in rows:
                conn.execute("""INSERT INTO replay_runs(run_id,user_id,dataset_name,total_records,blocked_records,allowed_records,policies_created,containment_rate,throughput_fps,elapsed_seconds,status,metadata)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(run_id,user_id) DO UPDATE SET dataset_name=EXCLUDED.dataset_name,total_records=EXCLUDED.total_records,blocked_records=EXCLUDED.blocked_records,allowed_records=EXCLUDED.allowed_records,policies_created=EXCLUDED.policies_created,containment_rate=EXCLUDED.containment_rate,throughput_fps=EXCLUDED.throughput_fps,elapsed_seconds=EXCLUDED.elapsed_seconds,status=EXCLUDED.status,metadata=EXCLUDED.metadata""",
                (r["run_id"],user_id,r["dataset_name"],r.get("total_records",0),r.get("blocked_records",0),r.get("allowed_records",0),r.get("policies_created",0),r.get("containment_rate"),r.get("throughput_fps"),r.get("elapsed_seconds"),r["status"],Jsonb(r.get("metadata") or {})))
        return {"stored":True,"backend":"neon_postgres","rows":len(rows)}
    if table not in EVENT_TABLES:return {"stored":False,"reason":"table_not_allowed"}
    with connect() as conn:
        for r in rows:conn.execute("INSERT INTO audit_events(user_id,event_type,run_id,payload) VALUES(%s,%s,%s,%s)",(user_id,table,r.get("run_id"),Jsonb(r)))
    return {"stored":True,"backend":"neon_postgres","rows":len(rows)}
def select_rows(table,query,user_id):
    if table not in {"replay_runs","replay_policies","replay_correlation_groups"}:return {"stored":False,"reason":"table_not_allowed","rows":[]}
    q=parse_qs(query,keep_blank_values=True);limit=max(1,min(int((q.get("limit") or ["50"])[0]),200));offset=max(0,int((q.get("offset") or ["0"])[0]));run=(q.get("run_id") or [""])[0]
    with connect() as conn:
        if table=="replay_runs":
            rows=conn.execute("SELECT run_id,dataset_name,total_records,blocked_records,allowed_records,policies_created,containment_rate,throughput_fps,elapsed_seconds,status,metadata,created_at FROM replay_runs WHERE user_id=%s ORDER BY created_at DESC LIMIT %s OFFSET %s",(user_id,limit,offset)).fetchall()
            return {"stored":True,"rows":[dict(x) for x in rows]}
        if run.startswith("eq."):rows=conn.execute("SELECT payload,created_at FROM audit_events WHERE user_id=%s AND event_type=%s AND run_id=%s ORDER BY created_at DESC LIMIT %s OFFSET %s",(user_id,table,run[3:],limit,offset)).fetchall()
        else:rows=conn.execute("SELECT payload,created_at FROM audit_events WHERE user_id=%s AND event_type=%s ORDER BY created_at DESC LIMIT %s OFFSET %s",(user_id,table,limit,offset)).fetchall()
    return {"stored":True,"rows":[{**x["payload"],"created_at":x["created_at"].isoformat()} for x in rows]}
def list_user_history(user_id,limit=15):
    limit=max(1,min(int(limit),50))
    with connect() as conn:
        runs=conn.execute("SELECT run_id,dataset_name,total_records,blocked_records,allowed_records,policies_created,containment_rate,throughput_fps,status,created_at FROM replay_runs WHERE user_id=%s ORDER BY created_at DESC LIMIT %s",(user_id,limit)).fetchall()
        ev=conn.execute("SELECT payload,created_at FROM audit_events WHERE user_id=%s AND event_type='analysis_runs' ORDER BY created_at DESC LIMIT %s",(user_id,limit)).fetchall()
    return {"runs":[dict(x) for x in runs],"evaluation_runs":[{**x["payload"],"created_at":x["created_at"].isoformat()} for x in ev],"source":"neon_postgres"}
