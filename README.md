# Center of Knowledge Deployment Guide

## Deployment split
- Database: Railway PostgreSQL
- Backend API: Railway
- Frontend: Vercel

## Local development
- Frontend: serve the `frontend/` folder locally on `http://localhost:5500`
- Backend: run `npm run dev` on `http://localhost:5501`
- Database: Laragon MySQL
- MySQL host: `127.0.0.1`
- MySQL port: `3306`
- MySQL user: `root`
- MySQL password: empty
- MySQL database: `spiritual_center`

## Environment files
- `.env`: local development values
- `.railway.env`: Railway backend values
- `.vercel.env`: Vercel frontend reference values

## Railway backend notes
- Use `DATABASE_URL` for the Railway backend service because it points to the internal Railway Postgres host.
- `DATABASE_PUBLIC_URL` is kept for external tools that need to reach the database from outside Railway.
- The backend now accepts both `DATABASE_URL` and the standard `PG*` variables directly.
- `railway.json` now points Railway health checks at `/api/health`.

## Frontend note
- `frontend/app-config.js` is the live runtime config for the static frontend.
- It now defaults non-local traffic to `https://center-of-knowledge-production.up.railway.app/api`.
- Keep that value updated if the Railway backend domain changes.

## File uploads
- This project still uses the existing optional Supabase storage integration for persistent uploads.
- If you want uploads to survive Railway redeploys, add persistent storage credentials.
- If you want temporary local `/uploads` storage instead, set `REQUIRE_PERSISTENT_STORAGE=false`.
