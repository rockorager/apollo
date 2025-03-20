CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  did TEXT NOT NULL UNIQUE,
  nick TEXT NOT NULL,
  modes INTEGER NOT NULL DEFAULT 0
);

-- nick index
CREATE INDEX IF NOT EXISTS idx_users_nick ON users(nick);

CREATE TABLE IF NOT EXISTS channels (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

-- channel name index
CREATE INDEX IF NOT EXISTS idx_channels_name ON channels(name);

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

CREATE TABLE IF NOT EXISTS read_marker (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  target_id INTEGER NOT NULL,
  target_kind INTEGER NOT NULL, -- 0 = channel, 1 = user
  timestamp_ms INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE (user_id, target_id, target_kind)
);

-- Create an index for the foreign keys
CREATE INDEX IF NOT EXISTS idx_read_marker_user_id ON read_marker(user_id);
CREATE INDEX IF NOT EXISTS idx_read_marker_target_id ON read_marker(target_id, target_kind);

-- Table to track channel membership
CREATE TABLE IF NOT EXISTS channel_membership (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  channel_id INTEGER NOT NULL,
  privileges INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (channel_id) REFERENCES channels(id),
  UNIQUE (user_id, channel_id)
);

CREATE TABLE IF NOT EXISTS user_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,          -- FK to users table
    password_hash TEXT,                -- Hashed app password
    refresh_token TEXT,                -- Refresh token
    refresh_expiry INTEGER,            -- Expiration timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
