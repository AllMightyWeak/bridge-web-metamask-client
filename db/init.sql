CREATE TABLE IF NOT EXISTS contacts (
  contact_id       SERIAL PRIMARY KEY,
  user_pub_key     varchar(42),
  contact_pub_key  varchar(132),
  contact_addr     varchar(42),
  contact_name     varchar(30),
  contact_network  varchar(85)
);

CREATE TABLE IF NOT EXISTS esia_wallet_links (
    id            BIGSERIAL    PRIMARY KEY,
    esia_user_id  TEXT         NOT NULL UNIQUE,
    eth_address   TEXT         NOT NULL UNIQUE,
    chain_id      BIGINT       NOT NULL,
    linked_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);