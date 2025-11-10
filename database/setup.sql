CREATE DATABASE IF NOT EXISTS matebeleng_cybersec;
USE matebeleng_cybersec;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user', 'instructor') NOT NULL DEFAULT 'user',
    language ENUM('en', 'st') NOT NULL DEFAULT 'en',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sample admin user (password: admin123)
INSERT INTO users (username, email, password_hash, role, language) 
VALUES ('admin', 'admin@matebelengcarwash.co.ls', '$2b$12$K3V3s9s1s8s7s6s5s4s3s2s1s0s9s8s7s6s5s4s3s2s1s0s9s8s7s6s', 'admin', 'en');

-- Categories table
CREATE TABLE IF NOT EXISTS categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name_en VARCHAR(100) NOT NULL,
    name_st VARCHAR(100) NOT NULL,
    description_en TEXT,
    description_st TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Quizzes table
CREATE TABLE IF NOT EXISTS quizzes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title_en VARCHAR(200) NOT NULL,
    title_st VARCHAR(200) NOT NULL,
    category_id INT,
    difficulty ENUM('easy', 'medium', 'hard') NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Questions table
CREATE TABLE IF NOT EXISTS questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    quiz_id INT NOT NULL,
    question_text_en TEXT NOT NULL,
    question_text_st TEXT NOT NULL,
    option_a_en VARCHAR(255) NOT NULL,
    option_a_st VARCHAR(255) NOT NULL,
    option_b_en VARCHAR(255) NOT NULL,
    option_b_st VARCHAR(255) NOT NULL,
    option_c_en VARCHAR(255),
    option_c_st VARCHAR(255),
    option_d_en VARCHAR(255),
    option_d_st VARCHAR(255),
    correct_option ENUM('a', 'b', 'c', 'd') NOT NULL,
    explanation_en TEXT,
    explanation_st TEXT,
    points INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
);

-- Quiz attempts table
CREATE TABLE IF NOT EXISTS quiz_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    quiz_id INT NOT NULL,
    score INT NOT NULL,
    total_questions INT NOT NULL,
    percentage DECIMAL(5,2) NOT NULL,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (quiz_id) REFERENCES quizzes(id)
);

-- Insert sample categories
INSERT INTO categories (name_en, name_st, description_en, description_st) VALUES
('Phishing Awareness', 'Tsebo ea Phishing', 'Learn to identify phishing attempts', 'Ithute ho tseba mekhoa ea phishing'),
('Password Security', 'Ts'ireletso ea Password', 'Best practices for password creation and management', 'Mekhoa e metle ea ho theha le ho laola password'),
('Data Protection', 'Ts'ireletso ea Data', 'Protecting sensitive information and data', 'Ho ts'ireletsa lintlha tse senyehang'),
('Social Engineering', 'Social Engineering', 'Recognizing and preventing social engineering attacks', 'Ho tseba le ho thibela mekhoa ea social engineering'),
('Mobile Security', 'Ts'ireletso ea Mobile', 'Securing mobile devices and applications', 'Ho ts'ireletsa lisebelisoa tse mobailing');

-- Insert sample quiz
INSERT INTO quizzes (title_en, title_st, category_id, difficulty, created_by) VALUES
('Basic Phishing Quiz', 'Quiz ea Phishing e Motlofu', 1, 'easy', 1);

-- Insert sample questions
INSERT INTO questions (quiz_id, question_text_en, question_text_st, option_a_en, option_a_st, option_b_en, option_b_st, option_c_en, option_c_st, option_d_en, option_d_st, correct_option, explanation_en, explanation_st) VALUES
(1, 'What is a common sign of a phishing email?', 'Ke eng lets''oao le tloaelehileng la email ea phishing?', 'Urgent action required', 'Ho hlokahala ketso ka potlako', 'Official company logo', 'Logo ea k''hamphani e la ''netse', 'Personalized greeting', 'Puo ea ho dumedisa e ikhethang', 'All of the above', 'Tsohle tse kaholimo', 'a', 'Phishing emails often create urgency to make you act without thinking.', 'Li-email tsa phishing li hlahisa khatello ea nako e khuts''oane ho u etsa hore u se ke ua nahana pele u etsa.'),
(1, 'You receive an email from your bank asking for your password. What should you do?', 'U fumana email ho tsoa bankeng ea hau e u kopang password ea hau. U lokela ho etsa eng?', 'Reply with your password', 'Araba ka password ea hau', 'Ignore and delete the email', 'Hlokomoloha le ho hlakola email', 'Forward to your bank''s security team', 'Romella ho sehlopha sa ts''ireletso sa banka ea hau', 'Click the link to verify', 'Tobetsa sehokelo ho netefatsa', 'c', 'Legitimate banks will never ask for your password via email.', 'Li-bank tsa ''nete li ke ke tla u kopa password ea hau ka email.'),
(1, 'Which of these URLs looks suspicious?', 'Ke life tsa li-URL tsena tse shebahalang tse susumetsang?', 'www.standardbank.co.ls', 'www.standardbank.co.ls', 'www.standardbank-security.com', 'www.standardbank-security.com', 'www.standardbank.update.com', 'www.standardbank.update.com', 'www.standardbank.co.ls/contact', 'www.standardbank.co.ls/contact', 'c', 'Domains that add extra words before the actual company name are often suspicious.', 'Li-domain tse kenang mantswe a eketsehileng pele lebitso la k''hamphani li susumetsa haholo.');