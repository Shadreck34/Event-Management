# Church Planner Event Management

## Deployment Instructions

### 1. Environment Variables
Copy `.env.example` to `.env` and fill in your production secrets and database credentials.

**Important:**
- Set a strong `SECRET_KEY`.
- Set `CORS_ORIGINS` to your frontend domain(s), e.g. `CORS_ORIGINS=https://yourdomain.com`

### 2. Install Dependencies
```
pip install -r requirements.txt
```

### 3. Run Database Migrations
Ensure your MySQL database is running and the schema is loaded (`schema.sql`).

### 4. Run with Production WSGI Server
- On Linux: `gunicorn -w 4 -b 0.0.0.0:5000 app:app`
- On Windows: `pip install waitress` then:
```
waitress-serve --port=5000 app:app
```

### 5. Static Files
Ensure your static files (CSS, JS) are served by your web server (Nginx, Apache, etc.) or Flask if needed.

### 6. Security
- Set a strong `SECRET_KEY` in your `.env`.
- Restrict CORS origins in `config.py` for production.
- Use HTTPS in production.

### 7. Troubleshooting
- Check logs for errors.
- Ensure all environment variables are set.
- Database user must have correct permissions.

---
