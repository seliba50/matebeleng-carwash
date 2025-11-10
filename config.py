import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'matebeleng-carwash-cybersecurity-2024'
    MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'localhost'
    MYSQL_USER = os.environ.get('MYSQL_USER') or 'root'
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or '12345678'
    MYSQL_DB = os.environ.get('MYSQL_DB') or 'matebeleng_cybersec'
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))