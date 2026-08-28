CREATE TABLE posts (
    id INT PRIMARY KEY,
    author_email VARCHAR(255),
    body TEXT
);

INSERT INTO posts (id, author_email, body) VALUES
(1, 'carol@example.com', 'Paragraph 1: Welcome!
Paragraph 2: This is a multi-line body with real newlines.
Paragraph 3: Semicolons; and (parentheses) inside quotes.'),
(2, 'dave@example.com', 'Single line body');
