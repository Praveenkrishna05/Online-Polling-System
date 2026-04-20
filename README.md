# Online Polling System

A Node.js + Express + MongoDB polling app with user voting and admin poll management.

## Features
- User registration and login with JWT auth
- Role-based access (`user`, `admin`)
- Admin poll create/edit/delete
- Vote tracking (one vote per user per poll)
- Poll likes
- Admin logs and vote analysis
- Health endpoint: `GET /api/health`

## Setup
1. Install dependencies:
   ```bash
   npm install
   ```
2. Create `.env` from `.env.example` and set real values.
3. Start server:
   ```bash
   npm start
   ```
4. Open: `http://localhost:3000`

## Environment Variables
- `PORT`: API port (default `3000`)
- `MONGO_URI`: MongoDB connection string
- `JWT_SECRET`: signing key for JWT
- `ADMIN_USERNAME` (optional): auto-create default admin on startup if missing
- `ADMIN_PASSWORD` (optional): password for default admin

## API Quick Check
- `GET /api/health`
  - Returns app status and database connection state.

## Maintenance Script
Run this if old poll docs are missing `votedBy`:
```bash
node updatepoll.js
```

## Git Workflow
Use this standard flow after changes:

```bash
git status
git add server.js public/index.html updatepoll.js README.md .env.example
git commit -m "Fix polling reliability, admin UX, and setup docs"
git push origin main
```

If you created or changed extra files, include them in `git add` too.
