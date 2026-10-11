-- ================================================================
--  SecureBank — sql/setup.sql
--  Run this ONCE in phpMyAdmin > SQL tab
--  Creates everything: database + tables + 5 triggers + seed data
-- ================================================================

CREATE DATABASE IF NOT EXISTS securebank_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securebank_db;

CREATE TABLE IF NOT EXISTS customers (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    customer_id VARCHAR(20)  UNIQUE NOT NULL,
    name        VARCHAR(150) NOT NULL,
    email       VARCHAR(150) UNIQUE NOT NULL,
    phone       VARCHAR(15)  NOT NULL,
    city        VARCHAR(100) DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS accounts (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    account_id          VARCHAR(20)   UNIQUE NOT NULL,
    customer_id         VARCHAR(20)   NOT NULL,
    account_type        VARCHAR(50)   NOT NULL,
    balance             DECIMAL(15,2) DEFAULT 0.00,
    status              ENUM('Active','Frozen') DEFAULT 'Active',
    password_changed_at DATETIME NULL,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS transactions (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    tx_id      VARCHAR(20)   UNIQUE NOT NULL,
    account_id VARCHAR(20)   NOT NULL,
    amount     DECIMAL(12,2) NOT NULL,
    tx_type    ENUM('Deposit','Withdraw','Transfer','ATM') NOT NULL,
    location   VARCHAR(100)  NOT NULL,
    flagged    TINYINT(1)    DEFAULT 0,
    tx_time    DATETIME      DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id),
    INDEX idx_acc_time (account_id, tx_time)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS fraud_alerts (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    alert_id       VARCHAR(20)  UNIQUE NOT NULL,
    transaction_id VARCHAR(20)  NOT NULL,
    account_id     VARCHAR(20)  NOT NULL,
    rule_name      VARCHAR(120) NOT NULL,
    severity       ENUM('HIGH','MEDIUM') DEFAULT 'HIGH',
    reason         TEXT NOT NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (transaction_id) REFERENCES transactions(tx_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS admin_users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_logs (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45)  DEFAULT '',
    status     ENUM('SUCCESS','FAILED') NOT NULL,
    logged_at  DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Default admin: username=admin  password=admin123
INSERT IGNORE INTO admin_users (username, password_hash)
VALUES ('admin', '$2y$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');

-- ================================================================
--  5 FRAUD DETECTION TRIGGERS
-- ================================================================
DELIMITER $$

DROP TRIGGER IF EXISTS trg_large_tx $$
CREATE TRIGGER trg_large_tx
AFTER INSERT ON transactions FOR EACH ROW
BEGIN
  IF NEW.amount > 50000 THEN
    INSERT INTO fraud_alerts (alert_id, transaction_id, account_id, rule_name, severity, reason)
    VALUES (CONCAT('ALT',LPAD(FLOOR(RAND()*999999),6,'0')), NEW.tx_id, NEW.account_id,
      'Rule 1 — Large Transaction', 'HIGH',
      CONCAT('Amount Rs.',FORMAT(NEW.amount,2),' exceeds Rs.50,000. Type: ',NEW.tx_type,' | Location: ',NEW.location));
  END IF;
END $$

DROP TRIGGER IF EXISTS trg_rapid_velocity $$
CREATE TRIGGER trg_rapid_velocity
AFTER INSERT ON transactions FOR EACH ROW
BEGIN
  DECLARE cnt INT DEFAULT 0;
  SELECT COUNT(*) INTO cnt FROM transactions
  WHERE account_id=NEW.account_id AND tx_id!=NEW.tx_id
    AND tx_time >= DATE_SUB(NEW.tx_time, INTERVAL 60 SECOND);
  IF cnt >= 4 THEN
    INSERT INTO fraud_alerts (alert_id, transaction_id, account_id, rule_name, severity, reason)
    VALUES (CONCAT('ALT',LPAD(FLOOR(RAND()*999999),6,'0')), NEW.tx_id, NEW.account_id,
      'Rule 2 — Rapid Velocity', 'HIGH',
      CONCAT(cnt+1,' transactions in 60 seconds on account ',NEW.account_id,'. Possible bot attack.'));
  END IF;
END $$

DROP TRIGGER IF EXISTS trg_location_anomaly $$
CREATE TRIGGER trg_location_anomaly
AFTER INSERT ON transactions FOR EACH ROW
BEGIN
  DECLARE prev_loc VARCHAR(100) DEFAULT NULL;
  DECLARE prev_time DATETIME    DEFAULT NULL;
  DECLARE diff INT              DEFAULT 0;
  SELECT location, tx_time INTO prev_loc, prev_time
  FROM transactions WHERE account_id=NEW.account_id AND tx_id!=NEW.tx_id
  ORDER BY tx_time DESC LIMIT 1;
  IF prev_loc IS NOT NULL AND prev_loc != NEW.location THEN
    SET diff = TIMESTAMPDIFF(MINUTE, prev_time, NEW.tx_time);
    IF diff < 10 THEN
      INSERT INTO fraud_alerts (alert_id, transaction_id, account_id, rule_name, severity, reason)
      VALUES (CONCAT('ALT',LPAD(FLOOR(RAND()*999999),6,'0')), NEW.tx_id, NEW.account_id,
        'Rule 3 — Location Anomaly', 'HIGH',
        CONCAT('Account ',NEW.account_id,' used in ',prev_loc,' then ',NEW.location,' within ',diff,' min. Impossible travel.'));
    END IF;
  END IF;
END $$

DROP TRIGGER IF EXISTS trg_atm_limit $$
CREATE TRIGGER trg_atm_limit
AFTER INSERT ON transactions FOR EACH ROW
BEGIN
  DECLARE daily DECIMAL(15,2) DEFAULT 0;
  IF NEW.tx_type = 'ATM' THEN
    SELECT COALESCE(SUM(amount),0) INTO daily FROM transactions
    WHERE account_id=NEW.account_id AND tx_type='ATM' AND DATE(tx_time)=DATE(NEW.tx_time);
    IF daily > 100000 THEN
      INSERT INTO fraud_alerts (alert_id, transaction_id, account_id, rule_name, severity, reason)
      VALUES (CONCAT('ALT',LPAD(FLOOR(RAND()*999999),6,'0')), NEW.tx_id, NEW.account_id,
        'Rule 4 — Daily ATM Limit', 'MEDIUM',
        CONCAT('Daily ATM total Rs.',FORMAT(daily,2),' exceeds Rs.1,00,000 for account ',NEW.account_id));
    END IF;
  END IF;
END $$

DROP TRIGGER IF EXISTS trg_account_takeover $$
CREATE TRIGGER trg_account_takeover
AFTER INSERT ON transactions FOR EACH ROW
BEGIN
  DECLARE pwd_time DATETIME DEFAULT NULL;
  DECLARE diff INT          DEFAULT 0;
  SELECT password_changed_at INTO pwd_time FROM accounts WHERE account_id=NEW.account_id;
  IF pwd_time IS NOT NULL THEN
    SET diff = TIMESTAMPDIFF(MINUTE, pwd_time, NEW.tx_time);
    IF diff >= 0 AND diff < 10 THEN
      INSERT INTO fraud_alerts (alert_id, transaction_id, account_id, rule_name, severity, reason)
      VALUES (CONCAT('ALT',LPAD(FLOOR(RAND()*999999),6,'0')), NEW.tx_id, NEW.account_id,
        'Rule 5 — Account Takeover', 'HIGH',
        CONCAT('Transaction Rs.',FORMAT(NEW.amount,2),' on ',NEW.account_id,' occurred ',diff,' min after password change.'));
    END IF;
  END IF;
END $$

DELIMITER ;

-- Sample Data
INSERT IGNORE INTO customers (customer_id,name,email,phone,city) VALUES
('CUST0001','Rahul Sharma','rahul.sharma@demo.com','9876543210','Mumbai'),
('CUST0002','Priya Singh','priya.singh@demo.com','9876543211','Delhi'),
('CUST0003','Amitabh Roy','amitabh.roy@demo.com','9876543212','Kolkata'),
('CUST0004','Sonal Mehta','sonal.mehta@demo.com','9876543213','Pune');

INSERT IGNORE INTO accounts (account_id,customer_id,account_type,balance,status) VALUES
('ACC0001','CUST0001','Savings',245000.00,'Active'),
('ACC0002','CUST0002','Current',580000.00,'Active'),
('ACC0003','CUST0003','Savings',120000.00,'Active'),
('ACC0004','CUST0004','Business',920000.00,'Active');
