import os
from datetime import timedelta

class Config:
    # MySQL Config
    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.getenv('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', '')
    MYSQL_DB = os.getenv('MYSQL_DB', 'church_planner_v2')

    # JWT/Secret Config
    SECRET_KEY = os.getenv('SECRET_KEY', 'bjwGBiG6WIM7L9B7BZ0vp-cnYoHo4c9mR_RCCZcmPc')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://127.0.0.1:5500,http://localhost:5500,http://localhost:3000').split(',')
