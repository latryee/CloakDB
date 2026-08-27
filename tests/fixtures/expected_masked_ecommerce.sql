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
27629	Jesus Newton	xyu@wayne-enterprises.com	+1-****0100	*******3333	0.0
22720	Angela Kim	jameswagner@dailyplanet.com	+1-****0200	*******6666	0.0
20022	Timothy Fisher	hsmith@themyscira.gov	+1-****0300	*******9999	0.0
\.

CREATE TABLE public.orders (
    order_id integer NOT NULL PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES public.customers(id),
    amount numeric(10,2),
    shipping_city varchar(50)
);

INSERT INTO public.orders (order_id, customer_id, amount, shipping_city) VALUES
(5001, 27629, 1200.5, 'CONFIDENTIAL'),
(5002, 22720, 45.0, 'CONFIDENTIAL'),
(5003, 27629, 350.0, 'CONFIDENTIAL');

CREATE TABLE public.secret_tokens (
    id integer NOT NULL PRIMARY KEY,
    token_val varchar(64)
);
