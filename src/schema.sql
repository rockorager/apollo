CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  did TEXT NOT NULL UNIQUE,
  nick TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS channels (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  uuid TEXT NOT NULL,
  timestamp_ms INTEGER NOT NULL,
  sender_id INTEGER NOT NULL, -- ID of the sender of the message
  sender_nick TEXT NOT NULL, -- Who sent the message. This is the nickname of the sender at the time of sending the message
  recipient_id INTEGER NOT NULL, -- Channel the message was sent to
  recipient_type INTEGER NOT NULL, -- 0 = channel, 1 = user. This is required to resolve the target foreign key
  message TEXT, -- Full text of the message, as received by the server
  FOREIGN KEY (sender_id) REFERENCES users(id)
);

-- Create an index for the target id and kind
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, recipient_type);
