-- CloakDB Sample PostgreSQL Database Dump
-- Contains realistic PII data for testing masking & anonymization

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

-- -------------------------------------------------------------
-- Table: users
-- -------------------------------------------------------------
CREATE TABLE public.users (
    id integer NOT NULL PRIMARY KEY,
    first_name varchar(50) NOT NULL,
    last_name varchar(50) NOT NULL,
    email varchar(100) NOT NULL UNIQUE,
    phone varchar(30),
    ssn varchar(20),
    credit_card varchar(25),
    salary numeric(10,2),
    birth_date date,
    ip_address varchar(45),
    created_at timestamp without time zone DEFAULT now()
);

COPY public.users (id, first_name, last_name, email, phone, ssn, credit_card, salary, birth_date, ip_address, created_at) FROM stdin;
1001	Eleanor	Vance	eleanor.vance@hillhouse.org	+1-555-0199	666-42-1920	4532015012345678	95000.00	1988-04-12	192.168.1.104	2023-01-15 10:20:00
1002	Luke	Sanderson	luke.sanderson@heritage.com	+1-555-0142	987-65-4321	5425233430109823	115000.50	1985-09-23	10.0.0.15	2023-02-20 14:45:10
1003	Theodora	Crain	theo.crain@designstudio.net	+1-555-0188	123-45-6789	378282246310005	82000.00	1991-11-05	172.16.254.1	2023-03-05 09:15:30
1004	Nell	Crain	nell.crain@redroom.co.uk	+44-20-7946-0912	555-12-8899	4916000000000003	74000.00	1994-06-18	88.198.24.50	2023-04-10 16:00:00
1005	Steven	Crain	steven.crain@authorpress.com	+1-555-0177	444-99-1122	6011111111111117	165000.00	1983-02-28	203.0.113.195	2023-05-01 11:30:45
\.

-- -------------------------------------------------------------
-- Table: orders (preserves foreign key user_id matching users.id)
-- -------------------------------------------------------------
CREATE TABLE public.orders (
    id integer NOT NULL PRIMARY KEY,
    user_id integer NOT NULL REFERENCES public.users(id),
    order_total numeric(10,2) NOT NULL,
    shipping_address text NOT NULL,
    customer_notes text,
    created_at timestamp without time zone DEFAULT now()
);

INSERT INTO public.orders (id, user_id, order_total, shipping_address, customer_notes, created_at) VALUES 
(501, 1001, 149.99, '742 Evergreen Terrace, Springfield, OR', 'Please leave package by the backdoor', '2023-06-01 12:00:00'),
(502, 1002, 349.50, '221B Baker Street, London, UK', 'Gate code is 4920', '2023-06-03 15:20:00'),
(503, 1001, 89.00, '742 Evergreen Terrace, Springfield, OR', 'Call Eleanor at 555-0199 upon arrival', '2023-06-10 09:40:00'),
(504, 1003, 520.00, '350 Fifth Avenue, New York, NY', 'Fragile glass art items', '2023-06-15 18:10:00');

-- -------------------------------------------------------------
-- Table: audit_logs (truncated table example)
-- -------------------------------------------------------------
CREATE TABLE public.audit_logs (
    id integer NOT NULL PRIMARY KEY,
    user_id integer,
    raw_payload text,
    ip_address varchar(45)
);

INSERT INTO public.audit_logs (id, user_id, raw_payload, ip_address) VALUES
(1, 1001, '{"action": "login", "password_attempt": "Secret123!"}', '192.168.1.104'),
(2, 1002, '{"action": "export", "records": 5000}', '10.0.0.15');
