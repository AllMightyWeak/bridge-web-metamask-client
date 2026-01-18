CREATE TABLE IF NOT EXISTS contacts (
  contact_id       SERIAL PRIMARY KEY,
  user_pub_key     varchar(42),
  contact_pub_key  varchar(132),
  contact_addr     varchar(42),
  contact_name     varchar(30),
  contact_network  varchar(85)
);
