-- ddos_ip
-- #######################
CREATE TABLE ddos_ip (
    timestamp DATETIME(6),
    label INT,
    malware_name VARCHAR(255),
    orig_bytes BIGINT,
    source_ip VARCHAR(255),
    source_port INT,
    destination_ip VARCHAR(255),
    destination_port INT,
    conn_duration DECIMAL(15,6),
    conn_history VARCHAR(255)
);

-- Local
SET autocommit = 0;
SET foreign_key_checks = 0;
SET unique_checks = 0; 
LOAD DATA LOCAL INFILE '/home/jon/Documents/Grad_School/AIT580/Project/reports/traffic_vol/ddos_report.csv' INTO TABLE ddos_ip
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n';
COMMIT;
SET foreign_key_checks = 1;
SET unique_checks = 1;
SET autocommit = 1;

-- AWS RDS
LOAD DATA LOCAL INFILE 'ddos_report.csv'
INTO TABLE ddos_ip
FIELDS TERMINATED BY ',' 
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
(timestamp, label, malware_name, orig_bytes, source_ip, source_port, destination_ip, destination_port, conn_duration, conn_history); 

-- This allows for faster sorts and lookups 
ALTER TABLE ddos_ip ADD INDEX idx_timestamp_source_ip (timestamp, source_ip);

CREATE TABLE ddos_attack_ip AS
SELECT timestamp, malware_name, source_ip, conn_duration, conn_history, orig_bytes
FROM ddos_ip
WHERE timestamp BETWEEN '2018-12-21' AND '2018-12-23';


-- ddos_conn
-- #######################
CREATE TABLE ddos_conn (
    timestamp DATETIME(6),
    label INT,
    malware_name VARCHAR(255),
    orig_bytes BIGINT,
    conn_duration DECIMAL(15,6),
    conn_state VARCHAR(255),
    conn_history VARCHAR(255)
);

-- Local
SET autocommit = 0;
SET foreign_key_checks = 0;
SET unique_checks = 0; 
LOAD DATA LOCAL INFILE '/home/jon/Documents/Grad_School/AIT580/Project/reports/traffic_vol/ddos_report_conn.csv' INTO TABLE ddos_conn
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n';
COMMIT;
SET foreign_key_checks = 1;
SET unique_checks = 1;
SET autocommit = 1;

-- RDS
LOAD DATA LOCAL INFILE 'ddos_report_conn.csv'
INTO TABLE ddos_conn
FIELDS TERMINATED BY ',' 
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
(timestamp, label, malware_name, orig_bytes, conn_duration, conn_history, conn_history); 

-- AWS 

-- EC2 instance 
sudo dnf install mariadb105
aws s3 cp s3://iot23-lab/ddos_report.csv .
aws s3 cp s3://iot23-lab/ddos_report_conn.csv .
-- by the time this project is over this domain will no longer exist. 
mysql -h lab-11-db.cilyigpmpbiz.us-east-1.rds.amazonaws.com -P 3306 -u admin -p 

-- Queries
-- all conn hist  
SELECT conn_history, COUNT(*) AS total_count
FROM ddos_ip
where malware_name = 'DDoS'
GROUP BY conn_history
ORDER BY total_count DESC
LIMIT 20;

-- conn hist attack 1  
SELECT 
    conn_history, 
    COUNT(*) AS total_count
FROM 
    ddos_ip
WHERE 
    timestamp BETWEEN '2018-12-21 23:07:59' AND '2018-12-21 23:08:15'
    AND malware_name = 'DDoS'
GROUP BY 
    conn_history
ORDER BY 
    total_count DESC
LIMIT 20;

-- conn hist attack 2  
SELECT 
    conn_history, 
    COUNT(*) AS total_count
FROM 
    ddos_ip
WHERE 
    timestamp BETWEEN '2019-01-10 14:00:00' AND '2019-01-10 18:00:00'
    AND malware_name = 'DDoS'
GROUP BY 
    conn_history
ORDER BY 
    total_count DESC
LIMIT 20;

-- all conn_state  
SELECT 
    conn_state, 
    COUNT(*) AS total_count
FROM 
    ddos_conn
WHERE 
    malware_name = 'DDoS'
GROUP BY 
    conn_history
ORDER BY 
    total_count DESC
LIMIT 20;

-- conn_state attack 1  
SELECT 
    conn_state, 
    COUNT(*) AS total_count
FROM 
    ddos_conn
WHERE 
    timestamp BETWEEN '2018-12-21 23:07:59' AND '2018-12-21 23:08:15'
    AND malware_name = 'DDoS'
GROUP BY 
    conn_history
ORDER BY 
    total_count DESC
LIMIT 20;

-- conn_state attack 2  
SELECT 
    conn_state, 
    COUNT(*) AS total_count
FROM 
    ddos_conn
WHERE 
    timestamp BETWEEN '2019-01-10 14:00:00' AND '2019-01-10 18:00:00'
    AND malware_name = 'DDoS'
GROUP BY 
    conn_history
ORDER BY 
    total_count DESC
LIMIT 20;

-- number of ports ALL - source_port
SELECT source_ip, COUNT(DISTINCT source_port) AS total_unique_ports
FROM ddos_ip
WHERE malware_name = 'DDoS'
GROUP BY source_ip
ORDER BY total_unique_ports DESC;

-- number of ports attack 1 - source_port
SELECT 
    source_ip, 
    COUNT(DISTINCT source_port) AS total_count
FROM 
    ddos_ip
WHERE 
    timestamp BETWEEN '2018-12-21 23:07:59' AND '2018-12-21 23:08:15'
    AND malware_name = 'DDoS'
GROUP BY 
    source_ip
ORDER BY 
    total_count DESC
LIMIT 20;

-- number of ports attack 2 - source_port
SELECT 
    source_ip, 
    COUNT(DISTINCT source_port) AS total_count
FROM 
    ddos_ip
WHERE 
    timestamp BETWEEN '2019-01-10 14:00:00' AND '2019-01-10 18:00:00'
    AND malware_name = 'DDoS'
GROUP BY 
    source_ip
ORDER BY 
    total_count DESC
LIMIT 20;

-- Utils 
DELETE FROM ddos_conn LIMIT 1;
drop table ddos_attack;

SET global max_allowed_packet = 1073741824; -- Increase packet size to 1GB = 1073741824
SET @@session.wait_timeout = 28800; -- Time in seconds
SET @@session.interactive_timeout = 28800;

CREATE DATABASE mynewdb;

show databases;
use <db>;

drop table <>
drop database <>

