DROP TABLE IF EXISTS todos;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    task TEXT NOT NULL,
    completed TEXT NOT NULL DEFAULT 'no' CHECK (completed IN ('yes', 'no')),
    FOREIGN KEY(user_id) REFERENCES users(id)
);