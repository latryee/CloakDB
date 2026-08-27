-- Test E-Commerce SQL Dump
SET statement_timeout = 0;
SET client_encoding = 'UTF8';

CREATE TABLE public.customers (
    id integer NOT NULL PRIMARY KEY,
    full_name varchar(100) NOT NULL,
    email varchar(100) NOT NULL,
    phone varchar(30),
    ssn varchar(20),
    salary numeric(10,2)
);

COPY public.customers (id, full_name, email, phone, ssn, salary) FROM stdin;
101	Bruce Wayne	bruce@wayne-enterprises.com	+1-555-0100	111-22-3333	250000.00
102	Clark Kent	clark@dailyplanet.com	+1-555-0200	444-55-6666	65000.00
103	Diana Prince	diana@themyscira.gov	+1-555-0300	777-88-9999	95000.00
\.

CREATE TABLE public.orders (
    order_id integer NOT NULL PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES public.customers(id),
    amount numeric(10,2),
    shipping_city varchar(50)
);

INSERT INTO public.orders (order_id, customer_id, amount, shipping_city) VALUES
(5001, 101, 1200.50, 'Gotham'),
(5002, 102, 45.00, 'Metropolis'),
(5003, 101, 350.00, 'Gotham');

CREATE TABLE public.secret_tokens (
    id integer NOT NULL PRIMARY KEY,
    token_val varchar(64)
);

INSERT INTO public.secret_tokens (id, token_val) VALUES
(1, 'super_secret_auth_token_xyz');
