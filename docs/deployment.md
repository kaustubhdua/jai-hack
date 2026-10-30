# CyberSentinel: Deployment & Infrastructure Guide

**Platform:** Vercel (Frontend & Python Functions) + Supabase (Auth & Postgres)  

---

## 1. Vercel Configuration (`vercel.json`)

Vercel orchestrates both the Vite React frontend and the Python serverless API functions:

```json
{
  "builds": [
    { "src": "package.json", "use": "@vercel/static-build" },
    { "src": "api/index.py", "use": "@vercel/python" }
  ],
  "routes": [
    { "src": "/api/(.*)", "dest": "api/index.py" },
    { "handle": "filesystem" },
    { "src": "/(.*)", "dest": "/index.html" }
  ]
}
```

### Serverless Compatibility Considerations
1. **Lightweight Runtime Dependencies:** Heavy model training stacks (e.g. distributed XGBoost, PyTorch) are strictly excluded from serverless execution. Only pre-fitted scikit-learn model artifacts (`.joblib`) are loaded during inference.
2. **Memory Footprint:** The combined footprint of `model.joblib` artifacts is ~4.4 MB, loading in < 0.2s on cold starts.
3. **Fail-Closed Pattern:** If model artifacts are missing or unmounted, the API returns a standard `503 MODEL_NOT_READY` error rather than failing ungracefully.

---

## 2. Supabase Configuration

### Environment Variables
For local and production frontend environments:
```bash
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-publishable-anon-key
```

> **Security Rule:** Never expose the Supabase `service_role` secret in frontend environment variables. All browser client actions must use the publishable `anon` key governed by Row Level Security (RLS).

### Database Migration
Apply `supabase/schema.sql` via Supabase SQL Editor or CLI:
- Sets up `analysis_runs` and `flow_events` tables.
- Enables Row Level Security (RLS).
- Defines ownership policies ensuring users access only their own analysis history.

---

## 3. Verification & Build Commands

### Frontend Production Build
```bash
npm install
npm run build
```

### Automated Backend Tests
```bash
pytest
```
*All 27 automated tests must pass before opening a Pull Request.*
