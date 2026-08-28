CREATE TABLE messages (
    id INT PRIMARY KEY,
    sender_email VARCHAR(255),
    message_text TEXT
);

INSERT INTO messages (id, sender_email, message_text) VALUES
(1, 'alice@example.com', 'Hello; this is a test; with semicolons;'),
(2, 'bob@example.com', 'Second message; still in insert block;');
