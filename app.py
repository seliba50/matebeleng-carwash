import re
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from mysql.connector import Error
import bcrypt
from functools import wraps
from config import Config
import os
from datetime import datetime
import random
import string
import csv
import io

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database helper function
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=app.config.get('MYSQL_HOST', 'localhost'),
            user=app.config.get('MYSQL_USER', 'root'),
            password=app.config.get('MYSQL_PASSWORD', ''),
            database=app.config.get('MYSQL_DB', 'matebeleng_cybersec'),
            port=app.config.get('MYSQL_PORT', 3306)
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role, language):
        self.id = str(id)
        self.username = username
        self.email = email
        self.role = role
        self.language = language

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn:
        return None
        
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email, role, language FROM users WHERE id=%s AND is_active=TRUE", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            return User(user['id'], user['username'], user['email'], user['role'], user['language'])
        return None
    except Error as e:
        print(f"Error loading user: {e}")
        return None

# Translations
translations = {
    'en': {
        'app_name': 'Matebeleng Carwash Cybersecurity',
        'welcome': 'Welcome to Cybersecurity Awareness',
        'register': 'Register',
        'login': 'Login',
        'username': 'Username',
        'email': 'Email',
        'password': 'Password',
        'confirm_password': 'Confirm Password',
        'role': 'Role',
        'language': 'Language',
        'english': 'English',
        'sesotho': 'Sesotho',
        'user': 'User',
        'admin': 'Admin',
        'instructor': 'Instructor',
        'register_btn': 'Register',
        'login_btn': 'Login',
        'logout': 'Logout',
        'dashboard': 'Dashboard',
        'have_account': 'Already have an account? Login here',
        'no_account': "Don't have an account? Register here",
        'quizzes': 'Quizzes',
        'take_quiz': 'Take Quiz',
        'create_quiz': 'Create Quiz',
        'quiz_title': 'Quiz Title',
        'category': 'Category',
        'difficulty': 'Difficulty',
        'questions': 'Questions',
        'add_question': 'Add Question',
        'manage_questions': 'Manage Questions',
        'question_text': 'Question Text',
        'options': 'Options',
        'correct_answer': 'Correct Answer',
        'explanation': 'Explanation',
        'points': 'Points',
        'easy': 'Easy',
        'medium': 'Medium',
        'hard': 'Hard',
        'your_score': 'Your Score',
        'completed': 'Completed',
        'best_score': 'Best Score',
        'not_attempted': 'Not Attempted',
        'start_quiz': 'Start Quiz',
        'submit_quiz': 'Submit Quiz',
        'next_question': 'Next Question',
        'previous_question': 'Previous Question',
        'quiz_results': 'Quiz Results',
        'time_completed': 'Time Completed'
    },
    'st': {
        'app_name': "Matebeleng Carwash Ts'ireletso ea Cyber",
        'welcome': "Rea u amohela ho Ts'ireletso ea Cyber",
        'register': 'Ingodise',
        'login': 'Kena',
        'username': 'Lebitso la mosebedisi',
        'email': 'Email',
        'password': 'Password',
        'confirm_password': 'Netefatsa Password',
        'role': 'Boemo',
        'language': 'Puo',
        'english': 'Sekhooa',
        'sesotho': 'Sesotho',
        'user': 'Mosebedisi',
        'admin': 'Mohlokomeli',
        'instructor': 'Mosebelisi',
        'register_btn': 'Ingodisa',
        'login_btn': 'Kena',
        'logout': 'Tsoa',
        'dashboard': 'Dashboard',
        'have_account': "U se u na ak'haonte? Kena mona",
        'no_account': "Ha u na ak'haonte? Ingodisa mona",
        'quizzes': 'Li-Quiz',
        'take_quiz': 'Etsa Quiz',
        'create_quiz': 'Theha Quiz',
        'quiz_title': 'Sehlooho sa Quiz',
        'category': 'Mofuta',
        'difficulty': 'Boima',
        'questions': 'Lipotso',
        'add_question': 'Kenya Potso',
        'manage_questions': 'Laola Lipotso',
        'question_text': 'Mongolo oa Potso',
        'options': 'Likhetho',
        'correct_answer': 'Karabo e nepahetseng',
        'explanation': 'Tlhaloso',
        'points': 'Lintlha',
        'easy': 'Bonolo',
        'medium': 'Boemong',
        'hard': 'Thata',
        'your_score': 'Pointi tsa hau',
        'completed': 'E felile',
        'best_score': 'Pointi e Phahameng',
        'not_attempted': 'Ha e so etsoe',
        'start_quiz': 'Qala Quiz',
        'submit_quiz': 'Romella Quiz',
        'next_question': 'Potso e Latelang',
        'previous_question': 'Potso e Fetileng',
        'quiz_results': 'Sephetho sa Quiz',
        'time_completed': 'Nako e Felitseng'
    }
}

def get_translation(key):
    lang = session.get('language', 'en')
    return translations.get(lang, translations['en']).get(key, key)

@app.context_processor
def utility_processor():
    return dict(_=get_translation)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in ['en', 'st']:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'user')
        language = request.form.get('language', 'en')

        errors = []

        if len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            errors.append('Invalid email address')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters long')
        if password != confirm_password:
            errors.append('Passwords do not match')

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return render_template('register.html')
            
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
            if cursor.fetchone():
                errors.append('Username or email already exists')

            if errors:
                cursor.close()
                conn.close()
                for e in errors:
                    flash(e, 'danger')
                return render_template('register.html')

            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, language, is_active) VALUES (%s,%s,%s,%s,%s,%s)",
                (username, email, password_hash, role, language, True)
            )
            conn.commit()
            cursor.close()
            conn.close()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Error as e:
            flash('Database error during registration', 'danger')
            cursor.close()
            conn.close()
            return render_template('register.html')

    return render_template('register.html')

# UPDATED LOGIN ROUTE WITH ACTIVITY TRACKING
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return render_template('login.html')
            
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email=%s AND is_active=TRUE", (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                user_obj = User(user['id'], user['username'], user['email'], user['role'], user.get('language','en'))
                login_user(user_obj)
                session['language'] = user.get('language','en')
                
                # Update login stats
                cursor.execute("""
                    UPDATE users 
                    SET last_login = NOW(), login_count = login_count + 1 
                    WHERE id = %s
                """, (user['id'],))
                
                # Log login activity
                cursor.execute("""
                    INSERT INTO system_activity_log (user_id, activity_type, description, ip_address, user_agent)
                    VALUES (%s, 'login', 'User logged in successfully', %s, %s)
                """, (user['id'], request.remote_addr, request.headers.get('User-Agent')))
                
                conn.commit()
                cursor.close()
                conn.close()

                flash(f'Welcome back, {user["username"]}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                # Log failed login attempt
                cursor.execute("""
                    INSERT INTO system_activity_log (activity_type, description, ip_address, user_agent)
                    VALUES ('failed_login', %s, %s, %s)
                """, (f'Failed login attempt for email: {email}', request.remote_addr, request.headers.get('User-Agent')))
                conn.commit()
                
                cursor.close()
                conn.close()
                flash('Invalid email or password', 'danger')
                
        except Error as e:
            flash('Database error during login', 'danger')
            cursor.close()
            conn.close()

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'username': current_user.username,
        'role': current_user.role,
        'email': current_user.email,
        'language': current_user.language
    }
    
    # Initialize default values
    user_stats = {}
    admin_stats = {}
    recent_activity = []
    
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            
            if current_user.role != 'admin':
                # Get user stats
                cursor.execute("""
                    SELECT 
                        COUNT(*) as quiz_attempts,
                        COALESCE(AVG(percentage), 0) as avg_score,
                        COUNT(DISTINCT c.id) as certificates,
                        COUNT(DISTINCT ua.achievement_id) as achievements
                    FROM users u
                    LEFT JOIN quiz_attempts qa ON u.id = qa.user_id
                    LEFT JOIN certificates c ON u.id = c.user_id AND c.is_active = TRUE
                    LEFT JOIN user_achievements ua ON u.id = ua.user_id
                    WHERE u.id = %s
                """, (current_user.id,))
                user_stats = cursor.fetchone() or {}
                
                # Get recent activity
                cursor.execute("""
                    SELECT 
                        'Quiz Completed' as title,
                        CONCAT('Scored ', qa.score, '/', qa.total_questions, ' on ', q.title_en) as description,
                        DATE(qa.completed_at) as timestamp
                    FROM quiz_attempts qa
                    JOIN quizzes q ON qa.quiz_id = q.id
                    WHERE qa.user_id = %s 
                    ORDER BY qa.completed_at DESC 
                    LIMIT 5
                """, (current_user.id,))
                recent_activity = cursor.fetchall()
                
            else:
                # Get admin stats
                cursor.execute("SELECT COUNT(*) as total_users FROM users")
                admin_stats['total_users'] = cursor.fetchone()['total_users']
                
                cursor.execute("SELECT COUNT(*) as active_quizzes FROM quizzes WHERE is_active = TRUE")
                admin_stats['active_quizzes'] = cursor.fetchone()['active_quizzes']
                
                cursor.execute("SELECT COUNT(*) as total_certificates FROM certificates WHERE is_active = TRUE")
                admin_stats['total_certificates'] = cursor.fetchone()['total_certificates']
                
                cursor.execute("SELECT COUNT(*) as quiz_attempts FROM quiz_attempts")
                admin_stats['quiz_attempts'] = cursor.fetchone()['quiz_attempts']
                
                # Get recent activity for admin
                cursor.execute("""
                    SELECT 
                        u.username,
                        'Quiz Completed' as title,
                        CONCAT('Scored ', qa.score, '/', qa.total_questions, ' on ', q.title_en) as description,
                        DATE(qa.completed_at) as timestamp
                    FROM quiz_attempts qa
                    JOIN quizzes q ON qa.quiz_id = q.id
                    JOIN users u ON qa.user_id = u.id
                    ORDER BY qa.completed_at DESC 
                    LIMIT 5
                """)
                recent_activity = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
        except Error as e:
            print(f"Error loading dashboard stats: {e}")
            # Ensure we have default values even if there's an error
            user_stats = {'quiz_attempts': 0, 'avg_score': 0, 'certificates': 0, 'achievements': 0}
            admin_stats = {'total_users': 0, 'active_quizzes': 0, 'total_certificates': 0, 'quiz_attempts': 0}
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         user_stats=user_stats,
                         admin_stats=admin_stats,
                         recent_activity=recent_activity)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('index'))

# Role requirement decorator
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != required_role:
                flash('Access denied. Insufficient permissions.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def sw():
    return send_from_directory('static/js', 'sw.js'), 200, {'Content-Type': 'application/javascript'}

# Add to your existing imports at the top
from flask import send_from_directory
# Quiz Management Routes
@app.route('/quizzes')
@login_required
def quizzes():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get available quizzes
        cursor.execute("""
            SELECT q.*, c.name_en as category_name_en, c.name_st as category_name_st 
            FROM quizzes q 
            LEFT JOIN categories c ON q.category_id = c.id 
            WHERE q.is_active = TRUE
        """)
        quizzes_list = cursor.fetchall()
        
        # Get user's quiz attempts
        cursor.execute("""
            SELECT quiz_id, MAX(percentage) as best_score 
            FROM quiz_attempts 
            WHERE user_id = %s 
            GROUP BY quiz_id
        """, (current_user.id,))
        user_scores = {attempt['quiz_id']: attempt['best_score'] for attempt in cursor.fetchall()}
        
        cursor.close()
        conn.close()
        
        return render_template('quizzes.html', quizzes=quizzes_list, user_scores=user_scores)
        
    except Error as e:
        flash('Error loading quizzes', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('quizzes'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get quiz details
        cursor.execute("""
            SELECT q.*, c.name_en as category_name_en, c.name_st as category_name_st 
            FROM quizzes q 
            LEFT JOIN categories c ON q.category_id = c.id 
            WHERE q.id = %s AND q.is_active = TRUE
        """, (quiz_id,))
        quiz = cursor.fetchone()
        
        if not quiz:
            flash('Quiz not found', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('quizzes'))
        
        # Get questions for this quiz
        cursor.execute("SELECT * FROM questions WHERE quiz_id = %s ORDER BY RAND()", (quiz_id,))
        questions = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        if not questions:
            flash('No questions available for this quiz', 'warning')
            return redirect(url_for('quizzes'))
        
        return render_template('take_quiz.html', quiz=quiz, questions=questions)
        
    except Error as e:
        flash('Error loading quiz', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('quizzes'))

# UPDATED SUBMIT_QUIZ ROUTE (WITH CERTIFICATE GENERATION)
@app.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    user_answers = request.form
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('quizzes'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get all questions for this quiz
        cursor.execute("SELECT * FROM questions WHERE quiz_id = %s", (quiz_id,))
        questions = cursor.fetchall()
        
        # Calculate score
        score = 0
        total_questions = len(questions)
        
        for question in questions:
            user_answer = user_answers.get(f'question_{question["id"]}')
            if user_answer and user_answer == question['correct_option']:
                score += question['points']
        
        percentage = (score / total_questions) * 100 if total_questions > 0 else 0
        
        # Save attempt
        cursor.execute("""
            INSERT INTO quiz_attempts (user_id, quiz_id, score, total_questions, percentage, certificate_eligible) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (current_user.id, quiz_id, score, total_questions, percentage, percentage >= 80))
        
        attempt_id = cursor.lastrowid
        
        # Create quiz completion notification
        cursor.execute("""
            SELECT title_en, title_st FROM quizzes WHERE id = %s
        """, (quiz_id,))
        quiz = cursor.fetchone()
        
        language = session.get('language', 'en')
        quiz_title = quiz['title_' + language] if quiz['title_' + language] else quiz['title_en']
        
        cursor.execute("""
            INSERT INTO notifications (user_id, title_en, title_st, message_en, message_st, notification_type, related_id)
            VALUES (%s, %s, %s, %s, %s, 'quiz_completed', %s)
        """, (
            current_user.id,
            "Quiz Completed!",
            "Quiz e Felile!",
            f"You scored {score}/{total_questions} ({percentage:.1f}%) on '{quiz['title_en']}'.",
            f"U fumane {score}/{total_questions} ({percentage:.1f}%) ho '{quiz['title_st']}'.",
            attempt_id
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Generate certificate if eligible
        if percentage >= 80:
            create_certificate(current_user.id, attempt_id)
        
        # Check for achievements
        check_and_award_achievements(current_user.id, attempt_id)
        
        flash(f'Quiz completed! Your score: {score}/{total_questions} ({percentage:.1f}%)', 'success')
        return redirect(url_for('quiz_results', attempt_id=attempt_id))
        
    except Error as e:
        flash('Error submitting quiz', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('quizzes'))

@app.route('/quiz/results/<int:attempt_id>')
@login_required
def quiz_results(attempt_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('quizzes'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get attempt details
        cursor.execute("""
            SELECT qa.*, q.title_en, q.title_st, u.username 
            FROM quiz_attempts qa 
            JOIN quizzes q ON qa.quiz_id = q.id 
            JOIN users u ON qa.user_id = u.id 
            WHERE qa.id = %s AND qa.user_id = %s
        """, (attempt_id, current_user.id))
        attempt = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not attempt:
            flash('Results not found', 'danger')
            return redirect(url_for('quizzes'))
        
        return render_template('quiz_results.html', attempt=attempt)
        
    except Error as e:
        flash('Error loading quiz results', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('quizzes'))

# Admin Quiz Management Routes
@app.route('/admin/quizzes')
@login_required
@role_required('admin')
def admin_quizzes():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT q.*, c.name_en as category_name_en, c.name_st as category_name_st, u.username as created_by_name 
            FROM quizzes q 
            LEFT JOIN categories c ON q.category_id = c.id 
            LEFT JOIN users u ON q.created_by = u.id 
            ORDER BY q.created_at DESC
        """)
        quizzes = cursor.fetchall()
        
        cursor.execute("SELECT * FROM categories")
        categories = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_quizzes.html', quizzes=quizzes, categories=categories)
        
    except Error as e:
        flash('Error loading admin quizzes', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/admin/quiz/create', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_quiz():
    if request.method == 'POST':
        title_en = request.form.get('title_en', '').strip()
        title_st = request.form.get('title_st', '').strip()
        category_id = request.form.get('category_id')
        difficulty = request.form.get('difficulty', 'easy')
        
        if not title_en or not title_st or not category_id:
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('create_quiz'))
        
        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return redirect(url_for('admin_quizzes'))
            
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quizzes (title_en, title_st, category_id, difficulty, created_by) 
                VALUES (%s, %s, %s, %s, %s)
            """, (title_en, title_st, category_id, difficulty, current_user.id))
            
            conn.commit()
            quiz_id = cursor.lastrowid
            cursor.close()
            conn.close()
            
            flash('Quiz created successfully! Now add questions.', 'success')
            return redirect(url_for('manage_questions', quiz_id=quiz_id))
            
        except Error as e:
            flash('Error creating quiz', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('admin_quizzes'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_quizzes'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM categories")
        categories = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('create_quiz.html', categories=categories)
        
    except Error as e:
        flash('Error loading categories', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_quizzes'))

@app.route('/admin/quiz/<int:quiz_id>/questions')
@login_required
@role_required('admin')
def manage_questions(quiz_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_quizzes'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM quizzes WHERE id = %s", (quiz_id,))
        quiz = cursor.fetchone()
        
        if not quiz:
            flash('Quiz not found', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('admin_quizzes'))
        
        cursor.execute("SELECT * FROM questions WHERE quiz_id = %s ORDER BY id", (quiz_id,))
        questions = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('manage_questions.html', quiz=quiz, questions=questions)
        
    except Error as e:
        flash('Error loading questions', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_quizzes'))

@app.route('/admin/quiz/<int:quiz_id>/questions/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_question(quiz_id):
    if request.method == 'POST':
        question_text_en = request.form.get('question_text_en', '').strip()
        question_text_st = request.form.get('question_text_st', '').strip()
        option_a_en = request.form.get('option_a_en', '').strip()
        option_a_st = request.form.get('option_a_st', '').strip()
        option_b_en = request.form.get('option_b_en', '').strip()
        option_b_st = request.form.get('option_b_st', '').strip()
        option_c_en = request.form.get('option_c_en', '').strip()
        option_c_st = request.form.get('option_c_st', '').strip()
        option_d_en = request.form.get('option_d_en', '').strip()
        option_d_st = request.form.get('option_d_st', '').strip()
        correct_option = request.form.get('correct_option', 'a')
        explanation_en = request.form.get('explanation_en', '').strip()
        explanation_st = request.form.get('explanation_st', '').strip()
        points = int(request.form.get('points', 1))
        
        # Validate required fields
        if not all([question_text_en, question_text_st, option_a_en, option_a_st, option_b_en, option_b_st]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('add_question', quiz_id=quiz_id))
        
        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return redirect(url_for('manage_questions', quiz_id=quiz_id))
            
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO questions 
                (quiz_id, question_text_en, question_text_st, option_a_en, option_a_st, option_b_en, option_b_st, 
                 option_c_en, option_c_st, option_d_en, option_d_st, correct_option, explanation_en, explanation_st, points) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (quiz_id, question_text_en, question_text_st, option_a_en, option_a_st, option_b_en, option_b_st,
                  option_c_en, option_c_st, option_d_en, option_d_st, correct_option, explanation_en, explanation_st, points))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Question added successfully!', 'success')
            return redirect(url_for('manage_questions', quiz_id=quiz_id))
            
        except Error as e:
            flash('Error adding question', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('manage_questions', quiz_id=quiz_id))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_quizzes'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM quizzes WHERE id = %s", (quiz_id,))
        quiz = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not quiz:
            flash('Quiz not found', 'danger')
            return redirect(url_for('admin_quizzes'))
        
        return render_template('add_question.html', quiz=quiz)
        
    except Error as e:
        flash('Error loading quiz', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_quizzes'))

@app.route('/admin/quiz/<int:quiz_id>/toggle', methods=['POST'])
@login_required
@role_required('admin')
def toggle_quiz(quiz_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_quizzes'))
        
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE quizzes SET is_active = NOT is_active WHERE id = %s", (quiz_id,))
        conn.commit()
        
        cursor.execute("SELECT is_active FROM quizzes WHERE id = %s", (quiz_id,))
        quiz = cursor.fetchone()
        cursor.close()
        conn.close()
        
        status = "activated" if quiz[0] else "deactivated"
        flash(f'Quiz {status} successfully!', 'success')
        return redirect(url_for('admin_quizzes'))
        
    except Error as e:
        flash('Error toggling quiz status', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_quizzes'))
    
@app.route('/learning')
@login_required
def learning_resources():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get learning resources
        cursor.execute("""
            SELECT lr.*, c.name_en as category_name_en, c.name_st as category_name_st 
            FROM learning_resources lr 
            LEFT JOIN categories c ON lr.category_id = c.id 
            WHERE lr.is_active = TRUE 
            ORDER BY lr.created_at DESC
        """)
        resources = cursor.fetchall()
        
        # Get user progress
        cursor.execute("""
            SELECT resource_id, completed, time_spent_minutes 
            FROM user_learning_progress 
            WHERE user_id = %s
        """, (current_user.id,))
        user_progress = {progress['resource_id']: progress for progress in cursor.fetchall()}
        
        # Get learning statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_resources,
                SUM(CASE WHEN completed THEN 1 ELSE 0 END) as completed_resources,
                SUM(time_spent_minutes) as total_learning_time
            FROM user_learning_progress
            WHERE user_id = %s
        """, (current_user.id,))
        learning_stats = cursor.fetchone()
        
        # Get quiz statistics for the stats card
        cursor.execute("""
            SELECT 
                AVG(percentage) as average_score
            FROM quiz_attempts 
            WHERE user_id = %s
        """, (current_user.id,))
        quiz_stats = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        # Ensure learning_stats has default values if None
        if not learning_stats:
            learning_stats = {
                'total_resources': 0,
                'completed_resources': 0,
                'total_learning_time': 0
            }
        
        return render_template('learning_resources.html', 
                             resources=resources, 
                             user_progress=user_progress,
                             learning_stats=learning_stats,
                             stats=quiz_stats)
        
    except Error as e:
        flash('Error loading learning resources', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/learning/resource/<int:resource_id>')
@login_required
def view_learning_resource(resource_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('learning_resources'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get resource details
        cursor.execute("""
            SELECT lr.*, c.name_en as category_name_en, c.name_st as category_name_st 
            FROM learning_resources lr 
            LEFT JOIN categories c ON lr.category_id = c.id 
            WHERE lr.id = %s AND lr.is_active = TRUE
        """, (resource_id,))
        resource = cursor.fetchone()
        
        if not resource:
            flash('Learning resource not found', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('learning_resources'))
        
        # Update user progress
        cursor.execute("""
            INSERT INTO user_learning_progress (user_id, resource_id, category_id, last_accessed) 
            VALUES (%s, %s, %s, NOW()) 
            ON DUPLICATE KEY UPDATE last_accessed = NOW()
        """, (current_user.id, resource_id, resource['category_id']))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return render_template('view_learning_resource.html', resource=resource)
        
    except Error as e:
        flash('Error loading learning resource', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('learning_resources'))

@app.route('/learning/complete/<int:resource_id>', methods=['POST'])
@login_required
def mark_resource_completed(resource_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database error'})
        
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_learning_progress (user_id, resource_id, completed, last_accessed) 
            VALUES (%s, %s, TRUE, NOW()) 
            ON DUPLICATE KEY UPDATE completed = TRUE, last_accessed = NOW()
        """, (current_user.id, resource_id))
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Resource marked as completed'})
        
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Database error'})

@app.route('/analytics')
@login_required
def user_analytics():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get user's quiz statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_attempts,
                AVG(percentage) as average_score,
                MAX(percentage) as best_score,
                MIN(percentage) as worst_score,
                SUM(time_taken_seconds) as total_time_seconds
            FROM quiz_attempts 
            WHERE user_id = %s
        """, (current_user.id,))
        stats = cursor.fetchone()
        
        # Get category-wise performance
        cursor.execute("""
            SELECT 
                c.name_en as category_name_en,
                c.name_st as category_name_st,
                COUNT(qa.id) as attempt_count,
                AVG(qa.percentage) as average_score,
                MAX(qa.percentage) as best_score
            FROM quiz_attempts qa
            JOIN quizzes q ON qa.quiz_id = q.id
            JOIN categories c ON q.category_id = c.id
            WHERE qa.user_id = %s
            GROUP BY c.id, c.name_en, c.name_st
            ORDER BY attempt_count DESC
        """, (current_user.id,))
        category_stats = cursor.fetchall()
        
        # Get recent attempts
        cursor.execute("""
            SELECT qa.*, q.title_en, q.title_st, c.name_en as category_name_en, c.name_st as category_name_st
            FROM quiz_attempts qa
            JOIN quizzes q ON qa.quiz_id = q.id
            LEFT JOIN categories c ON q.category_id = c.id
            WHERE qa.user_id = %s
            ORDER BY qa.completed_at DESC
            LIMIT 5
        """, (current_user.id,))
        recent_attempts = cursor.fetchall()
        
        # Get learning progress
        cursor.execute("""
            SELECT 
                COUNT(*) as total_resources,
                SUM(CASE WHEN completed THEN 1 ELSE 0 END) as completed_resources,
                SUM(time_spent_minutes) as total_learning_time
            FROM user_learning_progress
            WHERE user_id = %s
        """, (current_user.id,))
        learning_stats = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        # Ensure all variables have default values if None
        if not stats:
            stats = {
                'total_attempts': 0,
                'average_score': 0,
                'best_score': 0,
                'worst_score': 0,
                'total_time_seconds': 0
            }
        
        if not learning_stats:
            learning_stats = {
                'total_resources': 0,
                'completed_resources': 0,
                'total_learning_time': 0
            }
        
        # Calculate additional metrics
        if stats['total_attempts'] > 0:
            stats['improvement_trend'] = "Analyzing..."  # Placeholder for trend analysis
        else:
            stats['improvement_trend'] = "No data yet"
            
        return render_template('user_analytics.html', 
                             stats=stats, 
                             category_stats=category_stats,
                             recent_attempts=recent_attempts,
                             learning_stats=learning_stats)
        
    except Error as e:
        flash('Error loading analytics', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/quiz/detailed_results/<int:attempt_id>')
@login_required
def detailed_quiz_results(attempt_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('quizzes'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get attempt details
        cursor.execute("""
            SELECT qa.*, q.title_en, q.title_st, u.username 
            FROM quiz_attempts qa 
            JOIN quizzes q ON qa.quiz_id = q.id 
            JOIN users u ON qa.user_id = u.id 
            WHERE qa.id = %s AND qa.user_id = %s
        """, (attempt_id, current_user.id))
        attempt = cursor.fetchone()
        
        if not attempt:
            flash('Results not found', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('quizzes'))
        
        # Get questions for this quiz
        cursor.execute("SELECT * FROM questions WHERE quiz_id = %s", (attempt['quiz_id'],))
        questions = cursor.fetchall()
        
        # Create detailed results manually since quiz_question_results might not exist
        detailed_results = []
        user_answers = request.args  # In a real app, you'd store these somewhere
        
        for question in questions:
            # For now, we'll show all questions without user answers
            # In a complete implementation, you'd store user answers in quiz_question_results
            result = {
                **question,
                'user_answer': None,
                'is_correct': None,
                'user_answer_text_en': 'Not recorded',
                'user_answer_text_st': 'Ha e so bolokoe',
                'correct_answer_text_en': getattr(question, f"option_{question['correct_option']}_en", ''),
                'correct_answer_text_st': getattr(question, f"option_{question['correct_option']}_st", '')
            }
            detailed_results.append(result)
        
        # Get recommendations based on quiz category
        recommendations = []
        if attempt['quiz_id']:
            cursor.execute("""
                SELECT lr.* 
                FROM learning_resources lr 
                WHERE lr.category_id = (
                    SELECT category_id FROM quizzes WHERE id = %s
                ) AND lr.is_active = TRUE 
                LIMIT 3
            """, (attempt['quiz_id'],))
            recommendations = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('detailed_quiz_results.html', 
                             attempt=attempt, 
                             detailed_results=detailed_results,
                             recommendations=recommendations)
        
    except Error as e:
        flash('Error loading detailed results', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('quizzes'))

@app.route('/recommendations')
@login_required
def personalized_recommendations():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get user's weak categories based on quiz performance
        cursor.execute("""
            SELECT 
                c.id as category_id,
                c.name_en as category_name_en,
                c.name_st as category_name_st,
                COUNT(qa.id) as total_attempts,
                AVG(qa.percentage) as average_score
            FROM quiz_attempts qa
            JOIN quizzes q ON qa.quiz_id = q.id
            JOIN categories c ON q.category_id = c.id
            WHERE qa.user_id = %s
            GROUP BY c.id, c.name_en, c.name_st
            HAVING average_score < 70 OR total_attempts = 0
            ORDER BY average_score ASC
        """, (current_user.id,))
        weak_categories = cursor.fetchall()
        
        # Get recommended resources for weak categories
        recommendations = []
        for category in weak_categories:
            cursor.execute("""
                SELECT lr.* 
                FROM learning_resources lr 
                WHERE lr.category_id = %s AND lr.is_active = TRUE 
                AND lr.id NOT IN (
                    SELECT resource_id FROM user_learning_progress 
                    WHERE user_id = %s AND completed = TRUE
                )
                ORDER BY lr.difficulty ASC
                LIMIT 2
            """, (category['category_id'], current_user.id))
            category_recommendations = cursor.fetchall()
            if category_recommendations:
                recommendations.append({
                    'category': category,
                    'resources': category_recommendations
                })
        
        # Get general recommendations for unvisited resources
        cursor.execute("""
            SELECT lr.*, c.name_en as category_name_en, c.name_st as category_name_st
            FROM learning_resources lr
            LEFT JOIN categories c ON lr.category_id = c.id
            WHERE lr.is_active = TRUE 
            AND lr.id NOT IN (
                SELECT resource_id FROM user_learning_progress WHERE user_id = %s
            )
            ORDER BY lr.created_at DESC
            LIMIT 5
        """, (current_user.id,))
        general_recommendations = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('personalized_recommendations.html',
                             recommendations=recommendations,
                             general_recommendations=general_recommendations,
                             weak_categories=weak_categories)
        
    except Error as e:
        flash('Error loading recommendations', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))
    
# Certificate and Notifications Routes
@app.route('/notifications')
@login_required
def user_notifications():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get user notifications
        cursor.execute("""
            SELECT * FROM notifications 
            WHERE user_id = %s 
            ORDER BY created_at DESC
            LIMIT 50
        """, (current_user.id,))
        notifications = cursor.fetchall()
        
        # Mark as read when viewing
        cursor.execute("""
            UPDATE notifications 
            SET is_read = TRUE 
            WHERE user_id = %s AND is_read = FALSE
        """, (current_user.id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return render_template('notifications.html', notifications=notifications)
        
    except Error as e:
        flash('Error loading notifications', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/notifications/clear', methods=['POST'])
@login_required
def clear_notifications():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database error'})
        
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM notifications WHERE user_id = %s", (current_user.id,))
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Notifications cleared'})
        
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Database error'})

@app.route('/certificates')
@login_required
def user_certificates():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get user certificates with quiz details
        cursor.execute("""
            SELECT c.*, q.title_en, q.title_st, qa.score, qa.total_questions, qa.percentage
            FROM certificates c
            JOIN quiz_attempts qa ON c.quiz_attempt_id = qa.id
            JOIN quizzes q ON qa.quiz_id = q.id
            WHERE c.user_id = %s AND c.is_active = TRUE
            ORDER BY c.issued_at DESC
        """, (current_user.id,))
        certificates = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('certificates.html', certificates=certificates)
        
    except Error as e:
        flash('Error loading certificates', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/certificate/download/<int:certificate_id>')
@login_required
def download_certificate(certificate_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('user_certificates'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Verify certificate belongs to user and get details
        cursor.execute("""
            SELECT c.*, u.username, u.email, q.title_en, q.title_st, qa.score, qa.total_questions, qa.percentage
            FROM certificates c
            JOIN users u ON c.user_id = u.id
            JOIN quiz_attempts qa ON c.quiz_attempt_id = qa.id
            JOIN quizzes q ON qa.quiz_id = q.id
            WHERE c.id = %s AND c.user_id = %s AND c.is_active = TRUE
        """, (certificate_id, current_user.id))
        
        certificate = cursor.fetchone()
        
        if not certificate:
            flash('Certificate not found', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('user_certificates'))
        
        # For now, we'll create a simple HTML certificate
        # In production, you would generate a PDF using libraries like ReportLab or WeasyPrint
        certificate_html = generate_certificate_html(certificate)
        
        cursor.close()
        conn.close()
        
        return render_template('certificate_view.html', 
                             certificate=certificate, 
                             certificate_html=certificate_html)
        
    except Error as e:
        flash('Error loading certificate', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('user_certificates'))

def generate_certificate_html(certificate_data):
    """Generate HTML representation of certificate"""
    language = session.get('language', 'en')
    
    if language == 'st':
        title = "Setifikeiti sa Tsebo ea Ts'ireletso ea Cyber"
        awarded_to = "E filoe ho:"
        for_successful = " Bakeng sa ho atleha ho:"
        score_achieved = "Pointi e fumaneng:"
        date_issued = "Letsatsi le filoeng:"
        certificate_number = "Nomoro ea Setifikeiti:"
        congratulations = "Re u lakaletsa nyakallo! U fumane setifikeiti sena hobane u supile tsebo e phahameng ka ts'ireletso ea cyber."
        organization = "Matebeleng Carwash Cybersecurity Initiative"
    else:
        title = "Cybersecurity Awareness Certificate"
        awarded_to = "Awarded to:"
        for_successful = "For successful completion of:"
        score_achieved = "Score Achieved:"
        date_issued = "Date Issued:"
        certificate_number = "Certificate Number:"
        congratulations = "Congratulations! You've earned this certificate for demonstrating high cybersecurity awareness knowledge."
        organization = "Matebeleng Carwash Cybersecurity Initiative"
    
    html = f"""
    <div class="certificate-container" style="border: 5px solid gold; padding: 40px; background: white; max-width: 800px; margin: 0 auto; font-family: Arial, sans-serif;">
        <div class="certificate-header" style="text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px;">
            <h1 style="color: #2c3e50; margin: 0; font-size: 36px;">{title}</h1>
            <p style="color: #7f8c8d; font-size: 18px; margin: 10px 0 0 0;">{organization}</p>
        </div>
        
        <div class="certificate-body" style="text-align: center; padding: 20px 0;">
            <p style="font-size: 20px; margin: 20px 0;">{awarded_to} <strong style="font-size: 24px;">{certificate_data['username']}</strong></p>
            
            <p style="font-size: 18px; margin: 20px 0;">
                {for_successful}<br>
                <strong style="font-size: 22px;">
                    {certificate_data['title_' + language] if certificate_data['title_' + language] else certificate_data['title_en']}
                </strong>
            </p>
            
            <div style="display: flex; justify-content: space-around; margin: 30px 0;">
                <div>
                    <p style="font-size: 16px; margin: 5px 0;">{score_achieved}</p>
                    <p style="font-size: 24px; font-weight: bold; color: #27ae60; margin: 5px 0;">
                        {certificate_data['score']}/{certificate_data['total_questions']} ({certificate_data['percentage']}%)
                    </p>
                </div>
                <div>
                    <p style="font-size: 16px; margin: 5px 0;">{date_issued}</p>
                    <p style="font-size: 18px; font-weight: bold; margin: 5px 0;">
                        {certificate_data['issued_at'].strftime('%B %d, %Y') if certificate_data['issued_at'] else 'N/A'}
                    </p>
                </div>
            </div>
            
            <p style="font-size: 16px; color: #7f8c8d; margin: 20px 0;">
                {certificate_number} {certificate_data['certificate_number']}
            </p>
            
            <div class="congratulations" style="margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                <p style="font-size: 16px; font-style: italic; margin: 0;">{congratulations}</p>
            </div>
        </div>
        
        <div class="certificate-footer" style="border-top: 2px solid #333; padding-top: 20px; text-align: center;">
            <div style="display: flex; justify-content: space-around;">
                <div>
                    <p style="margin: 5px 0; font-weight: bold;">Director</p>
                    <p style="margin: 5px 0; color: #7f8c8d;">Matebeleng Carwash</p>
                </div>
                <div>
                    <p style="margin: 5px 0; font-weight: bold;">Cybersecurity Coordinator</p>
                    <p style="margin: 5px 0; color: #7f8c8d;">Training Department</p>
                </div>
            </div>
        </div>
    </div>
    """
    
    return html

def check_and_award_achievements(user_id, quiz_attempt_id=None):
    """Check and award achievements based on user progress"""
    conn = get_db_connection()
    if not conn:
        return
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get user's current stats
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT qa.id) as total_attempts,
                COUNT(DISTINCT qa.quiz_id) as unique_quizzes,
                MAX(qa.percentage) as best_score,
                COUNT(DISTINCT ulp.resource_id) as completed_resources
            FROM users u
            LEFT JOIN quiz_attempts qa ON u.id = qa.user_id
            LEFT JOIN user_learning_progress ulp ON u.id = ulp.user_id AND ulp.completed = TRUE
            WHERE u.id = %s
            GROUP BY u.id
        """, (user_id,))
        
        user_stats = cursor.fetchone()
        if not user_stats:
            user_stats = {'total_attempts': 0, 'unique_quizzes': 0, 'best_score': 0, 'completed_resources': 0}
        
        # Get current achievements
        cursor.execute("""
            SELECT ua.achievement_id 
            FROM user_achievements ua 
            WHERE ua.user_id = %s
        """, (user_id,))
        current_achievements = [row['achievement_id'] for row in cursor.fetchall()]
        
        # Get all available achievements
        cursor.execute("SELECT * FROM achievements WHERE is_active = TRUE")
        achievements = cursor.fetchall()
        
        new_achievements = []
        
        for achievement in achievements:
            if achievement['id'] in current_achievements:
                continue
                
            earned = False
            if achievement['criteria_type'] == 'attempts':
                earned = user_stats['total_attempts'] >= achievement['criteria_value']
            elif achievement['criteria_type'] == 'score':
                earned = user_stats['best_score'] >= achievement['criteria_value']
            elif achievement['criteria_type'] == 'completion':
                earned = user_stats['completed_resources'] >= achievement['criteria_value']
            elif achievement['criteria_type'] == 'streak':
                # Simple streak calculation - in production, you'd track actual streaks
                earned = user_stats['total_attempts'] >= achievement['criteria_value']
            
            if earned:
                # Award achievement
                cursor.execute("""
                    INSERT INTO user_achievements (user_id, achievement_id) 
                    VALUES (%s, %s)
                """, (user_id, achievement['id']))
                
                # Create notification
                cursor.execute("""
                    INSERT INTO notifications (user_id, title_en, title_st, message_en, message_st, notification_type, related_id)
                    VALUES (%s, %s, %s, %s, %s, 'achievement', %s)
                """, (
                    user_id,
                    f"Achievement Unlocked: {achievement['name_en']}",
                    f"Boemo bo notletsoe: {achievement['name_st']}",
                    f"Congratulations! You've earned the '{achievement['name_en']}' achievement. {achievement['description_en']}",
                    f"Re u lakaletsa nyakallo! U fumane boemo ba '{achievement['name_st']}'. {achievement['description_st']}",
                    cursor.lastrowid
                ))
                
                new_achievements.append(achievement)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return new_achievements
        
    except Error as e:
        print(f"Error checking achievements: {e}")
        cursor.close()
        conn.close()
        return []

def create_certificate(user_id, quiz_attempt_id):
    """Create a certificate for a quiz attempt"""
    conn = get_db_connection()
    if not conn:
        return None
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get quiz attempt details
        cursor.execute("""
            SELECT qa.*, q.title_en, q.title_st, u.username
            FROM quiz_attempts qa
            JOIN quizzes q ON qa.quiz_id = q.id
            JOIN users u ON qa.user_id = u.id
            WHERE qa.id = %s AND qa.user_id = %s
        """, (quiz_attempt_id, user_id))
        
        attempt = cursor.fetchone()
        
        if not attempt or attempt['percentage'] < 80:
            cursor.close()
            conn.close()
            return None
        
        # Generate certificate number
        certificate_number = f"MCW-CYB-{attempt['id']:06d}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"
        
        # Create certificate record
        cursor.execute("""
            INSERT INTO certificates (user_id, quiz_attempt_id, certificate_number, score, percentage)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, quiz_attempt_id, certificate_number, attempt['score'], attempt['percentage']))
        
        certificate_id = cursor.lastrowid
        
        # Create notification
        language = session.get('language', 'en')
        quiz_title = attempt['title_' + language] if attempt['title_' + language] else attempt['title_en']
        
        cursor.execute("""
            INSERT INTO notifications (user_id, title_en, title_st, message_en, message_st, notification_type, related_id)
            VALUES (%s, %s, %s, %s, %s, 'certificate_earned', %s)
        """, (
            user_id,
            "Certificate Earned!",
            "Setifikeiti se Fumanoe!",
            f"Congratulations! You've earned a certificate for scoring {attempt['percentage']}% on '{attempt['title_en']}'.",
            f"Re u lakaletsa nyakallo! U fumane setifikeiti ka ho fumana {attempt['percentage']}% ho '{attempt['title_st']}'.",
            certificate_id
        ))
        
        # Update quiz attempt
        cursor.execute("""
            UPDATE quiz_attempts 
            SET certificate_eligible = TRUE, certificate_generated = TRUE 
            WHERE id = %s
        """, (quiz_attempt_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Check for new achievements
        check_and_award_achievements(user_id, quiz_attempt_id)
        
        return certificate_id
        
    except Error as e:
        print(f"Error creating certificate: {e}")
        cursor.close()
        conn.close()
        return None

@app.route('/achievements')
@login_required
def user_achievements():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get user's earned achievements
        cursor.execute("""
            SELECT a.*, ua.earned_at
            FROM achievements a
            JOIN user_achievements ua ON a.id = ua.achievement_id
            WHERE ua.user_id = %s
            ORDER BY ua.earned_at DESC
        """, (current_user.id,))
        earned_achievements = cursor.fetchall()
        
        # Get all available achievements to show progress
        cursor.execute("SELECT * FROM achievements WHERE is_active = TRUE")
        all_achievements = cursor.fetchall()
        
        # Get user stats for progress calculation
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT qa.id) as total_attempts,
                MAX(qa.percentage) as best_score,
                COUNT(DISTINCT ulp.resource_id) as completed_resources
            FROM users u
            LEFT JOIN quiz_attempts qa ON u.id = qa.user_id
            LEFT JOIN user_learning_progress ulp ON u.id = ulp.user_id AND ulp.completed = TRUE
            WHERE u.id = %s
            GROUP BY u.id
        """, (current_user.id,))
        
        user_stats = cursor.fetchone()
        if not user_stats:
            user_stats = {'total_attempts': 0, 'best_score': 0, 'completed_resources': 0}
        
        cursor.close()
        conn.close()
        
        return render_template('achievements.html', 
                             earned_achievements=earned_achievements,
                             all_achievements=all_achievements,
                             user_stats=user_stats)
        
    except Error as e:
        flash('Error loading achievements', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

# ADMIN REPORTING ROUTES
@app.route('/admin/reports')
@login_required
@role_required('admin')
def admin_reports():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get system overview statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users,
                SUM(CASE WHEN last_login >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 ELSE 0 END) as active_30_days,
                AVG(login_count) as avg_logins_per_user
            FROM users
        """)
        user_stats = cursor.fetchone()
        
        # Get quiz statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_quizzes,
                SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_quizzes,
                COUNT(DISTINCT category_id) as categories_used
            FROM quizzes
        """)
        quiz_stats = cursor.fetchone()
        
        # Get learning resources statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_resources,
                SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_resources,
                COUNT(DISTINCT resource_type) as resource_types
            FROM learning_resources
        """)
        resource_stats = cursor.fetchone()
        
        # Get recent system activity
        cursor.execute("""
            SELECT sa.*, u.username 
            FROM system_activity_log sa 
            LEFT JOIN users u ON sa.user_id = u.id 
            ORDER BY sa.created_at DESC 
            LIMIT 10
        """)
        recent_activity = cursor.fetchall()
        
        # Get certificate statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_certificates,
                COUNT(DISTINCT user_id) as users_with_certificates,
                AVG(percentage) as avg_certificate_score
            FROM certificates 
            WHERE is_active = TRUE
        """)
        certificate_stats = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_reports.html',
                             user_stats=user_stats,
                             quiz_stats=quiz_stats,
                             resource_stats=resource_stats,
                             certificate_stats=certificate_stats,
                             recent_activity=recent_activity)
        
    except Error as e:
        flash('Error loading admin reports', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_reports'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get all users with their statistics
        cursor.execute("""
            SELECT 
                u.*,
                COUNT(qa.id) as quiz_attempts,
                COUNT(DISTINCT qa.quiz_id) as quizzes_taken,
                AVG(qa.percentage) as avg_score,
                MAX(qa.percentage) as best_score,
                COUNT(DISTINCT c.id) as certificates_earned,
                COUNT(DISTINCT ulp.resource_id) as resources_completed
            FROM users u
            LEFT JOIN quiz_attempts qa ON u.id = qa.user_id
            LEFT JOIN certificates c ON u.id = c.user_id AND c.is_active = TRUE
            LEFT JOIN user_learning_progress ulp ON u.id = ulp.user_id AND ulp.completed = TRUE
            GROUP BY u.id
            ORDER BY u.created_at DESC
        """)
        users = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_users.html', users=users)
        
    except Error as e:
        flash('Error loading users', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_reports'))

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
@role_required('admin')
def toggle_user_status(user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database error'})
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get current status
        cursor.execute("SELECT is_active FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        # Toggle status
        cursor.execute("UPDATE users SET is_active = NOT is_active WHERE id = %s", (user_id,))
        conn.commit()
        
        # Log the activity
        cursor.execute("""
            INSERT INTO system_activity_log (user_id, activity_type, description)
            VALUES (%s, 'user_management', %s)
        """, (current_user.id, f"{'Activated' if not user['is_active'] else 'Deactivated'} user ID: {user_id}"))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        status = "activated" if not user['is_active'] else "deactivated"
        return jsonify({'success': True, 'message': f'User {status} successfully!'})
        
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Database error'})

@app.route('/admin/export/<report_type>')
@login_required
@role_required('admin')
def export_report(report_type):
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_reports'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        if report_type == 'users':
            cursor.execute("""
                SELECT 
                    u.id, u.username, u.email, u.role, u.language, 
                    u.is_active, u.created_at, u.last_login, u.login_count,
                    COUNT(qa.id) as quiz_attempts,
                    AVG(qa.percentage) as avg_score,
                    COUNT(DISTINCT c.id) as certificates_earned
                FROM users u
                LEFT JOIN quiz_attempts qa ON u.id = qa.user_id
                LEFT JOIN certificates c ON u.id = c.user_id AND c.is_active = TRUE
                GROUP BY u.id
                ORDER BY u.created_at DESC
            """)
            data = cursor.fetchall()
            filename = f"users_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            csv_data = generate_csv(data, ['id', 'username', 'email', 'role', 'language', 'is_active', 'created_at', 'last_login', 'login_count', 'quiz_attempts', 'avg_score', 'certificates_earned'])
            
        elif report_type == 'quiz_attempts':
            cursor.execute("""
                SELECT 
                    qa.*,
                    u.username,
                    q.title_en as quiz_title,
                    c.name_en as category_name
                FROM quiz_attempts qa
                JOIN users u ON qa.user_id = u.id
                JOIN quizzes q ON qa.quiz_id = q.id
                LEFT JOIN categories c ON q.category_id = c.id
                ORDER BY qa.completed_at DESC
            """)
            data = cursor.fetchall()
            filename = f"quiz_attempts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            csv_data = generate_csv(data, ['id', 'username', 'quiz_title', 'category_name', 'score', 'total_questions', 'percentage', 'completed_at'])
            
        elif report_type == 'certificates':
            cursor.execute("""
                SELECT 
                    c.*,
                    u.username,
                    u.email,
                    q.title_en as quiz_title,
                    qa.score,
                    qa.total_questions,
                    qa.percentage
                FROM certificates c
                JOIN users u ON c.user_id = u.id
                JOIN quiz_attempts qa ON c.quiz_attempt_id = qa.id
                JOIN quizzes q ON qa.quiz_id = q.id
                WHERE c.is_active = TRUE
                ORDER BY c.issued_at DESC
            """)
            data = cursor.fetchall()
            filename = f"certificates_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            csv_data = generate_csv(data, ['certificate_number', 'username', 'email', 'quiz_title', 'score', 'total_questions', 'percentage', 'issued_at'])
            
        elif report_type == 'learning_progress':
            cursor.execute("""
                SELECT 
                    ulp.*,
                    u.username,
                    lr.title_en as resource_title,
                    lr.resource_type,
                    c.name_en as category_name
                FROM user_learning_progress ulp
                JOIN users u ON ulp.user_id = u.id
                JOIN learning_resources lr ON ulp.resource_id = lr.id
                LEFT JOIN categories c ON lr.category_id = c.id
                ORDER BY ulp.last_accessed DESC
            """)
            data = cursor.fetchall()
            filename = f"learning_progress_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            csv_data = generate_csv(data, ['username', 'resource_title', 'resource_type', 'category_name', 'completed', 'time_spent_minutes', 'last_accessed'])
            
        else:
            flash('Invalid report type', 'danger')
            return redirect(url_for('admin_reports'))
        
        # Log export activity
        cursor.execute("""
            INSERT INTO system_activity_log (user_id, activity_type, description)
            VALUES (%s, 'export', %s)
        """, (current_user.id, f"Exported {report_type} report"))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        response = app.response_class(
            csv_data,
            mimetype='text/csv',
            headers={'Content-disposition': f'attachment; filename={filename}'}
        )
        
        return response
        
    except Error as e:
        flash('Error generating export', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_reports'))

def generate_csv(data, fields):
    """Generate CSV data from database results"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(fields)
    
    # Write data rows
    for row in data:
        writer.writerow([row.get(field, '') for field in fields])
    
    return output.getvalue()

@app.route('/admin/analytics')
@login_required
@role_required('admin')
def admin_analytics():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_reports'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Daily activity for the last 30 days
        cursor.execute("""
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as activity_count,
                COUNT(DISTINCT user_id) as unique_users
            FROM system_activity_log 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        """)
        daily_activity = cursor.fetchall()
        
        # Quiz performance by category
        cursor.execute("""
            SELECT 
                c.name_en as category_name,
                c.name_st as category_name_st,
                COUNT(qa.id) as total_attempts,
                AVG(qa.percentage) as average_score,
                COUNT(DISTINCT qa.user_id) as unique_users
            FROM quiz_attempts qa
            JOIN quizzes q ON qa.quiz_id = q.id
            JOIN categories c ON q.category_id = c.id
            GROUP BY c.id, c.name_en, c.name_st
            ORDER BY total_attempts DESC
        """)
        category_performance = cursor.fetchall()
        
        # User engagement metrics
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN login_count = 0 THEN '0'
                    WHEN login_count BETWEEN 1 AND 5 THEN '1-5'
                    WHEN login_count BETWEEN 6 AND 20 THEN '6-20'
                    ELSE '20+'
                END as login_range,
                COUNT(*) as user_count,
                AVG(quiz_attempts) as avg_quiz_attempts,
                AVG(resources_completed) as avg_resources_completed
            FROM (
                SELECT 
                    u.id,
                    u.login_count,
                    COUNT(DISTINCT qa.id) as quiz_attempts,
                    COUNT(DISTINCT ulp.resource_id) as resources_completed
                FROM users u
                LEFT JOIN quiz_attempts qa ON u.id = qa.user_id
                LEFT JOIN user_learning_progress ulp ON u.id = ulp.user_id AND ulp.completed = TRUE
                GROUP BY u.id, u.login_count
            ) user_stats
            GROUP BY login_range
            ORDER BY login_range
        """)
        engagement_metrics = cursor.fetchall()
        
        # System usage statistics
        cursor.execute("""
            SELECT 
                'Total Users' as metric, 
                COUNT(*) as value 
            FROM users
            UNION ALL
            SELECT 
                'Active Users (30 days)', 
                COUNT(DISTINCT user_id) 
            FROM system_activity_log 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            UNION ALL
            SELECT 
                'Total Quiz Attempts', 
                COUNT(*) 
            FROM quiz_attempts
            UNION ALL
            SELECT 
                'Certificates Issued', 
                COUNT(*) 
            FROM certificates 
            WHERE is_active = TRUE
            UNION ALL
            SELECT 
                'Learning Resources Completed', 
                COUNT(*) 
            FROM user_learning_progress 
            WHERE completed = TRUE
        """)
        usage_stats = {row['metric']: row['value'] for row in cursor.fetchall()}
        
        cursor.close()
        conn.close()
        
        return render_template('admin_analytics.html',
                             daily_activity=daily_activity,
                             category_performance=category_performance,
                             engagement_metrics=engagement_metrics,
                             usage_stats=usage_stats)
        
    except Error as e:
        flash('Error loading analytics', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_reports'))

@app.route('/admin/system_logs')
@login_required
@role_required('admin')
def system_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_reports'))
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get total count
        cursor.execute("SELECT COUNT(*) as total FROM system_activity_log")
        total = cursor.fetchone()['total']
        
        # Get logs with pagination
        cursor.execute("""
            SELECT sa.*, u.username 
            FROM system_activity_log sa 
            LEFT JOIN users u ON sa.user_id = u.id 
            ORDER BY sa.created_at DESC 
            LIMIT %s OFFSET %s
        """, (per_page, offset))
        logs = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        total_pages = (total + per_page - 1) // per_page
        
        return render_template('system_logs.html',
                             logs=logs,
                             page=page,
                             total_pages=total_pages,
                             total=total)
        
    except Error as e:
        flash('Error loading system logs', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_reports'))

if __name__ == '__main__':
    app.run(debug=True)