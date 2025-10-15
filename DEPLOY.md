Deploying Church Planner (Free options)

This document walks through quick, free-friendly ways to deploy the project as-is. It assumes the repository root is the project folder that contains `backend/`, `frontend/`, `dist/`, `docker-compose.yml`, and the other files.

Quick summary (choices):

- Frontend only (easy, free): deploy `dist/` to Netlify or Vercel (static hosting). Use `scripts\build_frontend.ps1` to produce `dist/`.
- Full app (backend + DB) on free-tier PaaS: Railway or Render can host your Flask backend and managed MySQL. Both have free tiers with limitations.
- Local docker-compose: run everything locally with Docker (dev/test only).

1) Prepare frontend build (required before static hosting)

PowerShell (Windows):

```powershell
# From repository root
cd "c:\Users\shadrack soko\Documents\Event-Management"
# Build/copy frontend into dist/
.
# Run the included build script (optionally set API base)
.
# Example, no API_BASE replacement required if using relative API paths:
powershell -ExecutionPolicy Bypass -File .\scripts\build_frontend.ps1
```

2) Deploy frontend to Netlify (free, quick)

- Create a Netlify account and connect your GitHub repository OR use drag-and-drop.
- If you connect the repo, set the build command to none (we already produce `dist/` locally) and set the publish directory to `dist`.
- If you want Netlify to build for you from the repo, create a simple `netlify.toml` (example provided alongside).

Notes: Netlify does not proxy arbitrary backend endpoints by default. If your frontend calls `/api/*`, configure the API_BASE variable in JS to point to your hosted backend URL (Railway/Render) or use Netlify Functions as a proxy (advanced).

3) Deploy backend + MySQL to Railway (recommended free flow)

- Sign up at https://railway.app.
- Create a new project and add the MySQL plugin (create a database). Railway will provide environment variables: `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DB`.
- Deploy the backend from the repo (connect to GitHub) or use CLI to deploy from local. Ensure the `Dockerfile` in `backend/` is used.
- Add environment variables (SECRET_KEY, CORS_ORIGINS, etc.) in Railway settings.
- Run database migrations by applying `schema.sql` (use Railway's DB GUI or a CLI connection).
- After deployment, set the frontend `API_BASE` to the Railway backend URL.

4) Deploy backend to Render (alternative)

- Similar steps: create a Web Service, choose Dockerfile or Python, set env vars, add a Postgres/MySQL managed DB, and deploy.

5) Local docker-compose (for quick testing)

Requirements: Docker Desktop on Windows.

```powershell
# From project root
cd "c:\Users\shadrack soko\Documents\Event-Management"
# Create a .env with DB credentials or copy .env.example
cp .env.example .env
# Start services
docker-compose up --build -d
# View logs
docker-compose logs -f backend
```

6) Free-tier caveats

- Railway/Render free tiers sleep after inactivity and have resource limits.
- Netlify/Vercel static hosting is free but backend must be hosted separately.
- Local docker-compose is not public and meant for dev/testing.

7) Troubleshooting & checklist

- Ensure `SECRET_KEY` is set in production env.
- Update `CORS_ORIGINS` to include the frontend domain.
- Run `schema.sql` against your MySQL instance before using the app.
- If you see schedule errors, check server logs for type errors in `recalculate_event_schedule` (we've added defensive parsing already).

8) Next steps I can do for you (pick any):
- Connect this repo to Netlify and set `dist/` as publish directory (requires GitHub access).
- Deploy backend to Railway for you (requires linking/repo access and secrets).
- Run `docker-compose up` here to test locally (requires Docker installed on your machine and permission to run it).
- Create a simple GitHub Action to build `dist/` automatically on push.

---

Files added to the repo to help:
- `netlify.toml` (if you want Netlify to build from the repo)
- `DEPLOY.md` (this file)

