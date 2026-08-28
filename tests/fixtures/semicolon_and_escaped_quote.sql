CREATE TABLE comments (
    id INT PRIMARY KEY,
    author_email VARCHAR(255),
    comment_text TEXT
);

INSERT INTO comments (id, author_email, comment_text) VALUES
(1, 'alice@example.com', 'It''s a great feature; highly recommended!'),
(2, 'bob@example.com', 'Customer\'s feedback; status: resolved; notes: don''t forget follow-up.'),
(3, 'carol@example.com', 'Final note; let\'s verify.');
